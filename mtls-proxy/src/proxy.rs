

use std::{sync::Arc, time::Duration, future::Future};

use anyhow::Result;

use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use tokio_rustls::{TlsAcceptor, TlsConnector};
use rustls::pki_types::ServerName;          
use tracing::{error, info, warn};

use crate::{
    config::Config,
    tls,                                       
};


/// `Proxy` is a minimal mTLS side-car:
/// 1. Terminates **incoming** mutual TLS from local clients.
/// 2. Opens a fresh (m)TLS channel to an upstream service.
/// 3. Streams bytes in both directions.
///
/// All runtime settings (listen addr, upstream addr, certificate paths…)
/// are provided via a [`Config`] struct loaded from `proxy.yaml`.
///
/// All heavy objects are wrapped in `Arc`, so the `Proxy` can be cloned
/// cheaply into every Tokio task spawned per connection.


#[derive(Clone)]
pub struct Proxy {
    server_cfg: Arc<rustls::ServerConfig>,
    client_cfg: Arc<rustls::ClientConfig>,
    app_cfg: Config,
}

impl Proxy {

    /// Start the proxy:
    /// * runs the accept loop,
    /// * shuts down cleanly on **Ctrl-C**.
    ///
    /// # Errors
    /// Propagates any fatal error from the listener task; a clean Ctrl-C
    /// exit is **not** considered an error.

    pub async fn run(&self) -> Result<()> {
        info!("Starting mTLS proxy — listen={}, upstream={}", self.app_cfg.listen, self.app_cfg.upstream);

        tokio::select! {
            res = self.accept_loop() => {
                res
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Shutdown signal received (Ctrl-C). Closing proxy.");
                Ok(())
            }
        }
    }


    /// Bind a `TcpListener`, accept incoming TCP connections, and spawn one
    /// Tokio task per client.
    ///
    /// Each spawned task clones `self` (cheap `Arc` clone) and calls
    /// [`handle_connection`].  The loop never returns unless the listener
    /// itself fails.
    async fn accept_loop(&self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(&self.app_cfg.listen).await?;
        info!("Proxy listening on {}", self.app_cfg.listen);

        loop {
            let (sock,peer_addr) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    warn!("Failed to accept connection {}", e);
                    continue;
                }
            };
            let proxy = self.clone();

            tokio::spawn(async move {
                if let Err(e) = proxy.handle_connection(sock).await {
                    error!("Connection from {} ended with error {:?}", peer_addr, e);
                }
            });
        }

    }

    /// Perform the **server-side** mTLS handshake for an inbound socket.
    ///
    /// * Requires a valid **client certificate** (via
    ///   `rustls::AllowAnyAuthenticatedClient`).
    /// * ALPN is fixed to `h2`.
    ///
    /// # Parameters
    /// * `raw_conn` – the raw `TcpStream` accepted by the listener.
    ///
    /// # Returns
    /// An authenticated, encrypted `TlsStream`.
    ///
    /// # Errors
    /// Times out after 5 s via [`with_timeout`] or returns any rustls / I/O
    /// error produced during the handshake.
    async fn tls_accept(&self, raw_conn: TcpStream) -> anyhow::Result<tokio_rustls::server::TlsStream<TcpStream>>{
        let acceptor = TlsAcceptor::from(self.server_cfg.clone());
        let handshake = async {
            acceptor.accept(raw_conn).await.map_err(anyhow::Error::from)
        };

        let stream = self.with_timeout(handshake, Duration::from_secs(5)).await?;

        Ok(stream)
    }


    /// Dial the upstream address with a **client-side** (m)TLS handshake.
    ///
    /// Presents the proxy’s client certificate and validates the upstream
    /// server certificate against the configured CA.
    ///
    /// # Returns
    /// A fully negotiated `TlsStream<TcpStream>` ready for proxying.
    ///
    /// # Errors
    /// * Invalid `upstream` string (must be `host:port`).
    /// * Timeout after 10 s.
    /// * Any rustls / I/O error during the handshake.
    async fn connect_upstream(&self) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let connector = TlsConnector::from(self.client_cfg.clone());
        let tcp_stream = TcpStream::connect(&self.app_cfg.upstream).await?;

       
        let host = self.app_cfg.upstream.split(":").next().ok_or_else(|| anyhow::anyhow!("invalid upstream address"))?.to_owned();

        let server_name = ServerName::try_from(host)
            .map_err(|_| anyhow::anyhow!("invalid ServerName for upsream"))?;
        let handshake = async {
            connector.connect(server_name, tcp_stream).await.map_err(anyhow::Error::from)
        };

        self.with_timeout(handshake, Duration::from_secs(10)).await

    }
    
    /// Bi-directional byte pump between client and server.
    ///
    /// Wraps `tokio::io::copy_bidirectional` and logs total byte counts when
    /// either side closes.
    ///
    /// # Errors
    /// Propagates any I/O error raised while copying.
    async fn pipe(
        &self, 
        downstream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
        upstream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin)
        ) -> anyhow::Result<()> {
            match copy_bidirectional(downstream, upstream).await {
                Ok((from_client, from_server)) => {
                    info!("Connection closed. Bytes from client {}, from server {}", from_client, from_server);
                    Ok(())
                }
                Err(e) => {
                    error!("Error with piping data {}", e);
                    Err(e.into())
                }
            }

        }

    /// Build a fully-initialised [`Proxy`] from YAML configuration.
    ///
    /// Loads certificates/keys from disk and constructs both
    /// `rustls::ServerConfig` and `rustls::ClientConfig`.
    ///
    /// # Errors
    /// Returns an [`anyhow::Error`] if any file is missing or a certificate /
    /// key fails to parse.

    pub fn new(cfg: Config) -> anyhow::Result<Self> {
        let server_cfg = Arc::new(tls::build_server_config(&cfg.tls)?);
        let client_cfg = Arc::new(tls::build_client_config(&cfg.tls)?);
        
        Ok(Proxy {
            server_cfg,
            client_cfg,
            app_cfg: cfg,
        })
    }

    /// Handle one client session end-to-end:
    /// 1. Server-side mTLS via [`tls_accept`].
    /// 2. Client-side (m)TLS via [`connect_upstream`].
    /// 3. Stream bytes via [`pipe`].
    ///
    /// All per-connection errors are returned so the caller can log them.
    async fn handle_connection(&self, incoming: TcpStream) -> Result<()>{

        let mut downstream = match self.tls_accept(incoming).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Client TLS handshake failed {}", e);
                return Err(e);
            }

        };

        let mut upstream = match self.connect_upstream().await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to connect to upstream {}", e);
                return Err(e);
            }
        };

        self.pipe(&mut downstream, &mut upstream).await
    }


    /// Run an asynchronous operation with a hard deadline.
    ///
    /// # Parameters
    /// * `fut` – any `Future` that returns `anyhow::Result<T>`.
    /// * `dur` – maximum duration to wait.
    ///
    /// # Returns
    /// The inner success value if the future completes in time.
    ///
    /// # Errors
    /// * `anyhow!("Operation timed out …")` if the deadline is exceeded.
    /// * Any underlying error produced by `fut`.
    async fn with_timeout<F, T> (
        &self,
        fut: F,
        dur: Duration,
    ) -> anyhow::Result<T> where F: Future<Output = anyhow::Result<T>> {

        match timeout(dur, fut).await {
            Ok(inner_res) => inner_res,
            Err(_) => Err(anyhow::anyhow!("Operation timed out after {:?}", dur)),
        }
    }
}