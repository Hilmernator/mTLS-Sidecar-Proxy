use std::{fs::File, io::BufReader, sync::Arc, path::Path};



use rustls::{
    RootCertStore,                       
    server::WebPkiClientVerifier, 
    ServerConfig,         
    pki_types::{                         
        CertificateDer,                  
        PrivateKeyDer,                                         
    },
};
use tracing::{info, warn};

use tokio_rustls::TlsAcceptor;                                  
use hyper::{
    body::{Bytes, Incoming as Body},
    Request, Response,
};
use hyper::service::service_fn;
use http_body_util::Full;   
use hyper_util::{rt::TokioExecutor, server::conn::auto, rt::TokioIo};


use std::net::SocketAddr;
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio::net::TcpListener;
use anyhow::Result;


fn cert_reader<P: AsRef<Path>>(cert_path: P) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let cert_file = File::open(cert_path)?;
    let mut reader = BufReader::new(cert_file);
    let parsed = certs(&mut reader);

    let certs: Result<Vec<CertificateDer>, _> = parsed
        .map(|res| res.map(|cert_der| CertificateDer::from(cert_der)))
        .collect();
    Ok(certs?)
}

fn privkey_reader<P: AsRef<Path>>(key_path: P) -> anyhow::Result<PrivateKeyDer<'static>> {
    let key_file = File::open(key_path.as_ref())?;
    let mut reader = BufReader::new(key_file);

    let key = pkcs8_private_keys(&mut reader)
        .next()
        .transpose()?
        .ok_or_else(|| anyhow::anyhow!("no PKCS8 key found in {}", key_path.as_ref().display()))?;
    
    Ok(PrivateKeyDer::Pkcs8(key))
   
}

fn load_root_store<P: AsRef<Path>>(ca_path: P) -> anyhow::Result<RootCertStore> {
    let ca_certs = cert_reader(&ca_path.as_ref())?;
    
    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(ca_certs);

    if root_store.is_empty() {
        anyhow::bail!("CA-file did not contain any valid certs")
    }
    Ok(root_store)

}

#[tokio::main]
async fn main() -> Result<()>{
    tracing_subscriber::fmt::init();
    let ca_cert = "../mtls-certs/ca.crt";
    let server_cert = "../mtls-certs/upstream.crt";
    let server_key = "../mtls-certs/upstream.key";


    let certs = cert_reader(server_cert)?;
    let key = privkey_reader(server_key)?;
    let root_store = load_root_store(&ca_cert)?;
    let client_auth = WebPkiClientVerifier::builder(root_store.into()).build().unwrap();

    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(client_auth)
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(config));

    let addr: SocketAddr = "127.0.0.1:9443".parse().unwrap();
    let listener = TcpListener::bind(addr).await.expect("failed to bind to address");
    info!("mTLS Upstream server on https://{}", addr);

    // Async accept loop
    loop {
        let (tcp_stream, _) = listener.accept().await?;
        let peer_addr = tcp_stream.peer_addr().ok();
        let acceptor = acceptor.clone();

        //Service handler so that each tokio task gets its own instance.
        let svc = service_fn(|_req: Request<Body>| async move {
            let body = Full::new(Bytes::from_static(b"Hello from upstream"));
            Ok::<_, hyper::Error>(Response::new(body))
        });

        tokio::spawn(async move {
            match acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    info!("Accepted TLS connection from {:?}", peer_addr);
                    let io = TokioIo::new(tls_stream);

                    if let Err(err) = auto::Builder::new(TokioExecutor::new())
                        .serve_connection(io, svc)
                        .await
                    {
                        warn!("connection error {err:?}");
                    }
                }
                
                Err(e) => {
                    warn!("TLS handshake failed {e:?}");
                }
            }
        });

    }

}