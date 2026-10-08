//! Proxy and extra-CA settings for registry clients.
//!
//! [`RegistryClientProxy::load`] validates a [`RegistryProxy`] once, at runtime
//! creation. reqwest would accept some mistakes silently: a proxy URL with an
//! unknown scheme is dropped and the pull goes direct, and a CA file without
//! PEM certificates adds no trust.

use std::path::Path;

use boxlite_shared::errors::with_causes;
use boxlite_shared::{BoxliteError, BoxliteResult};
use oci_client::client::{Certificate, CertificateEncoding, ClientConfig};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;

use crate::runtime::options::RegistryProxy;

/// Validated [`RegistryProxy`] settings, applied to every registry client.
#[derive(Default)]
pub(super) struct RegistryClientProxy {
    http_proxy: Option<String>,
    https_proxy: Option<String>,
    no_proxy: Option<String>,
    extra_root_certificates: Vec<Certificate>,
}

impl RegistryClientProxy {
    /// Validate the proxy URLs and read the CA file. `None` leaves proxying to
    /// the environment variables.
    pub(super) fn load(proxy: Option<RegistryProxy>) -> BoxliteResult<Self> {
        let Some(proxy) = proxy else {
            return Ok(Self::default());
        };
        validate_proxy_url("http_proxy", proxy.http_proxy.as_deref())?;
        validate_proxy_url("https_proxy", proxy.https_proxy.as_deref())?;
        if proxy.no_proxy.is_some() && proxy.http_proxy.is_none() && proxy.https_proxy.is_none() {
            return Err(invalid("no_proxy requires http_proxy or https_proxy"));
        }
        let extra_root_certificates = match &proxy.ca_cert_path {
            Some(path) => vec![load_ca_certificate(path)?],
            None => Vec::new(),
        };
        let loaded = Self {
            http_proxy: proxy.http_proxy,
            https_proxy: proxy.https_proxy,
            no_proxy: proxy.no_proxy,
            extra_root_certificates,
        };

        // reqwest parses the URLs and certificates only when a client is built.
        let mut config = ClientConfig::default();
        loaded.apply(&mut config);
        oci_client::Client::try_from(config).map_err(|e| invalid(&with_causes(&e)))?;
        Ok(loaded)
    }

    /// Copy these settings into one registry client's configuration.
    pub(super) fn apply(&self, config: &mut ClientConfig) {
        config.http_proxy = self.http_proxy.clone();
        config.https_proxy = self.https_proxy.clone();
        config.no_proxy = self.no_proxy.clone();
        config.extra_root_certificates = self.extra_root_certificates.clone();
    }
}

fn validate_proxy_url(field: &str, url: Option<&str>) -> BoxliteResult<()> {
    let scheme = url.map(|url| url.split_once("://").map_or("", |(scheme, _)| scheme));
    match scheme.map(str::to_ascii_lowercase).as_deref() {
        None | Some("http" | "https") => Ok(()),
        Some(_) => Err(invalid(&format!(
            "{field} must be an http:// or https:// URL"
        ))),
    }
}

/// Check the file with the PEM parser reqwest uses, so a file it would load
/// as no certificates fails here.
fn load_ca_certificate(path: &Path) -> BoxliteResult<Certificate> {
    let reject = |reason: String| invalid(&format!("ca_cert_path {}: {reason}", path.display()));
    let pem = std::fs::read(path).map_err(|e| reject(format!("cannot read: {e}")))?;
    let certificates = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| reject(format!("not valid PEM: {e}")))?;
    if certificates.is_empty() {
        return Err(reject("contains no PEM certificates".to_string()));
    }
    Ok(Certificate {
        encoding: CertificateEncoding::Pem,
        data: pem,
    })
}

fn invalid(reason: &str) -> BoxliteError {
    BoxliteError::Config(format!("invalid registry_proxy: {reason}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BoxliteRuntime;
    use crate::runtime::options::{BoxliteOptions, ImageRegistry};
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    use serde_json::{Value, json};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    /// Pull an image through a runtime built with `settings`; nothing serves it.
    async fn pull_through(settings: Value) {
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let runtime = BoxliteRuntime::new_for_test(BoxliteOptions {
            home_dir: home.path().to_path_buf(),
            registry_proxy: Some(serde_json::from_value(settings).unwrap()),
            ..Default::default()
        })
        .unwrap();
        let images = runtime.images().unwrap();
        assert!(
            images
                .pull("registry.example.invalid/team/app:1")
                .await
                .is_err()
        );
    }

    /// An HTTP proxy recording each request's first line. Without `tls` it
    /// refuses every CONNECT; with it, it intercepts the tunnel's TLS.
    async fn fake_proxy(tls: Option<TlsAcceptor>) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                let connect = request_line(&mut tcp).await;
                log.lock().unwrap().push(connect);
                let Some(tls) = &tls else {
                    let _ = tcp.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    continue;
                };
                let _ = tcp.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
                if let Ok(mut tunnel) = tls.accept(tcp).await {
                    let request = request_line(&mut tunnel).await;
                    log.lock().unwrap().push(request);
                    let _ = tunnel.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n").await;
                }
            }
        });
        (url, seen)
    }

    async fn request_line(stream: &mut (impl AsyncRead + Unpin)) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && matches!(stream.read(&mut byte).await, Ok(1)) {
            head.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&head);
        head.lines().next().unwrap_or_default().to_string()
    }

    /// A CA's PEM, and an acceptor presenting a certificate it issued for the registry.
    fn intercepting_tls() -> (String, TlsAcceptor) {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["registry.example.invalid".to_string()])
            .unwrap()
            .signed_by(&leaf_key, &ca, &ca_key)
            .unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone()], key.into())
            .unwrap();
        (ca.pem(), TlsAcceptor::from(Arc::new(config)))
    }

    #[tokio::test]
    async fn pull_tunnels_through_https_proxy_unless_no_proxy_matches() {
        for (no_proxy, proxied) in [(None, true), (Some("example.invalid"), false)] {
            let (url, seen) = fake_proxy(None).await;
            pull_through(json!({ "https_proxy": url, "no_proxy": no_proxy })).await;

            let seen = seen.lock().unwrap().clone();
            let expected = "CONNECT registry.example.invalid:443 HTTP/1.1";
            assert_eq!(!seen.is_empty(), proxied, "{seen:?}");
            assert!(seen.iter().all(|line| line == expected), "{seen:?}");
        }
    }

    #[tokio::test]
    async fn pull_trusts_intercepting_proxy_only_with_its_ca() {
        let (ca_pem, tls) = intercepting_tls();
        let ca_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(ca_file.path(), ca_pem).unwrap();

        for ca_cert_path in [None, Some(ca_file.path())] {
            let (url, seen) = fake_proxy(Some(tls.clone())).await;
            pull_through(json!({ "https_proxy": url, "ca_cert_path": ca_cert_path })).await;

            // A request line arrives only once the TLS handshake succeeded.
            let seen = seen.lock().unwrap().clone();
            let reached_registry = seen.iter().any(|line| line.starts_with("GET /v2/"));
            assert_eq!(reached_registry, ca_cert_path.is_some(), "{seen:?}");
        }
    }

    /// Loading `settings` must fail with an error containing `expected`.
    fn assert_rejected(settings: Value, expected: &str) {
        let settings = serde_json::from_value(settings).unwrap();
        let Err(err) = RegistryClientProxy::load(Some(settings)) else {
            panic!("accepted settings that should fail with {expected:?}");
        };
        assert!(err.to_string().contains(expected), "{err}");
    }

    fn assert_ca_rejected(contents: &str, expected: &str) {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), contents).unwrap();
        assert_rejected(json!({ "ca_cert_path": file.path() }), expected);
    }

    #[test]
    fn load_rejects_settings_reqwest_would_ignore_or_misread() {
        assert_rejected(json!({ "https_proxy": "htp://p:3128" }), "https_proxy must");
        assert_rejected(json!({ "http_proxy": "p.corp:3128" }), "http_proxy must");
        assert_rejected(json!({ "https_proxy": "http://p:99999" }), "invalid port");
        assert_rejected(json!({ "no_proxy": "localhost" }), "no_proxy requires");
        assert_rejected(json!({ "ca_cert_path": "/missing.pem" }), "cannot read");

        let pem = |body| format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----");
        assert_ca_rejected("not a certificate\n", "contains no PEM");
        assert_ca_rejected(&pem("!!!!"), "not valid PEM");
        assert_ca_rejected(&pem("AAAA"), "invalid peer certificate");
    }

    #[test]
    fn invalid_options_fail_runtime_creation_as_config_errors() {
        let bad_proxy = serde_json::from_value(json!({ "https_proxy": "socks5://p:1080" }));
        let cases = [
            BoxliteOptions {
                registry_proxy: Some(bad_proxy.unwrap()),
                ..Default::default()
            },
            BoxliteOptions {
                image_registries: vec![ImageRegistry::https("https://registry.local")],
                ..Default::default()
            },
        ];
        for options in cases {
            let home = tempfile::tempdir_in("/tmp").unwrap();
            let options = BoxliteOptions {
                home_dir: home.path().to_path_buf(),
                ..options
            };
            match BoxliteRuntime::new_for_test(options) {
                Err(BoxliteError::Config(_)) => {}
                Err(other) => panic!("invalid options reported as {other}"),
                Ok(_) => panic!("invalid options accepted"),
            }
        }
    }
}
