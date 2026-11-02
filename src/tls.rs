//! TLS configurations (rustls + ring) and HTTP clients.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, pem::PemObject},
};

fn builder() -> Result<rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier>> {
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .context("TLS configuration")
}

/// Embedded Mozilla roots, independent of the system store.
pub fn webpki_config() -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Ok(builder()?.with_root_certificates(roots).with_no_client_auth())
}

/// Trusts a single CA (e.g. PIA's).
pub fn single_ca_config(pem: &[u8]) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(pem) {
        roots.add(cert.context("invalid PEM certificate")?).context("adding root certificate")?;
    }
    Ok(builder()?.with_root_certificates(roots).with_no_client_auth())
}

pub fn client_builder(tls: ClientConfig, timeout: Duration) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .no_proxy()
        .user_agent(concat!("ferrotun/", env!("CARGO_PKG_VERSION")))
}

pub fn web_client(timeout: Duration) -> Result<reqwest::Client> {
    Ok(client_builder(webpki_config()?, timeout).build()?)
}
