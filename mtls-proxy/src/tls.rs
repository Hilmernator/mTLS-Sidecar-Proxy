use std::{
    fs::File,
    io::BufReader,
    path::Path,
};

use rustls::{
    RootCertStore,                       
    server::WebPkiClientVerifier, 
    ServerConfig, ClientConfig,          
    pki_types::{                         
        CertificateDer,                  
        PrivateKeyDer,                                         
    },
};

use rustls_pemfile::{
    certs,
    pkcs8_private_keys,
};
use anyhow::Result;
use crate::config::TlsConfig;

pub fn cert_reader<P: AsRef<Path>>(cert_path: P) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let cert_file = File::open(cert_path)?;
    let mut reader = BufReader::new(cert_file);
    let parsed = certs(&mut reader);

    let certs: Result<Vec<CertificateDer>, _> = parsed
        .map(|res| res.map(|cert_der| CertificateDer::from(cert_der)))
        .collect();
    Ok(certs?)
}

pub fn privkey_reader<P: AsRef<Path>>(key_path: P) -> anyhow::Result<PrivateKeyDer<'static>> {
    let key_file = File::open(key_path.as_ref())?;
    let mut reader = BufReader::new(key_file);

    let key = pkcs8_private_keys(&mut reader)
        .next()
        .transpose()?
        .ok_or_else(|| anyhow::anyhow!("no PKCS8 key found in {}", key_path.as_ref().display()))?;
    
    Ok(PrivateKeyDer::Pkcs8(key))
   
}

pub fn load_root_store<P: AsRef<Path>>(ca_path: P) -> anyhow::Result<RootCertStore> {
    let ca_certs = cert_reader(&ca_path.as_ref())?;
    
    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(ca_certs);

    if root_store.is_empty() {
        anyhow::bail!("CA-file did not contain any valid certs")
    }
    Ok(root_store)

}

pub fn build_server_config(tls: &TlsConfig) -> Result<ServerConfig> {
    let server_cert = cert_reader(&tls.server_cert)?;
    let privkey_server = privkey_reader(&tls.server_key)?;
    let root_store = load_root_store(&tls.ca_file)?;

    let client_verifier = WebPkiClientVerifier::builder(root_store.into()).build().unwrap();

    let mut config = ServerConfig::builder()
    .with_client_cert_verifier(client_verifier)
    .with_single_cert(server_cert, privkey_server)?;

    config.alpn_protocols = vec![b"h2".to_vec()];

    Ok(config)
}


    
pub fn build_client_config(tls: &TlsConfig) -> Result<ClientConfig> {
    let client_cert = cert_reader(&tls.client_cert)?;
    let privkey_client = privkey_reader(&tls.client_key)?;
    let root_store = load_root_store(&tls.ca_file)?;

    

    let mut config = ClientConfig::builder()
    .with_root_certificates(root_store)
    .with_client_auth_cert(client_cert, privkey_client)?;

    config.alpn_protocols = vec![b"h2".to_vec()];

    Ok(config)
}


