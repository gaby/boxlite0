//! Proxy settings for registry clients.
//!
//! [`RegistryClientProxy::load`] validates a [`RegistryProxy`] once, at runtime
//! creation. reqwest would accept some mistakes silently: a proxy URL with an
//! unknown scheme is dropped and the pull goes direct.

use boxlite_shared::errors::with_causes;
use boxlite_shared::{BoxliteError, BoxliteResult};
use oci_client::client::ClientConfig;

use crate::runtime::options::RegistryProxy;

/// Validated [`RegistryProxy`] settings, applied to every registry client.
#[derive(Default)]
pub(super) struct RegistryClientProxy {
    http_proxy: Option<String>,
    https_proxy: Option<String>,
    no_proxy: Option<String>,
}

impl RegistryClientProxy {
    /// Validate the proxy URLs. `None` leaves proxying to the environment
    /// variables.
    pub(super) fn load(proxy: Option<RegistryProxy>) -> BoxliteResult<Self> {
        let Some(proxy) = proxy else {
            return Ok(Self::default());
        };
        validate_proxy_url("http_proxy", proxy.http_proxy.as_deref())?;
        validate_proxy_url("https_proxy", proxy.https_proxy.as_deref())?;
        if proxy.no_proxy.is_some() && proxy.http_proxy.is_none() && proxy.https_proxy.is_none() {
            return Err(invalid("no_proxy requires http_proxy or https_proxy"));
        }
        let loaded = Self {
            http_proxy: proxy.http_proxy,
            https_proxy: proxy.https_proxy,
            no_proxy: proxy.no_proxy,
        };

        // reqwest parses the URLs only when a client is built.
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

fn invalid(reason: &str) -> BoxliteError {
    BoxliteError::Config(format!("invalid registry_proxy: {reason}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BoxliteRuntime;
    use crate::runtime::options::{BoxliteOptions, ImageRegistry};
    use serde_json::{Value, json};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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

    /// An HTTP proxy that records each request's first line and refuses every CONNECT.
    async fn fake_proxy() -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                let connect = request_line(&mut tcp).await;
                log.lock().unwrap().push(connect);
                let _ = tcp.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
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

    #[tokio::test]
    async fn pull_tunnels_through_https_proxy_unless_no_proxy_matches() {
        for (no_proxy, proxied) in [(None, true), (Some("example.invalid"), false)] {
            let (url, seen) = fake_proxy().await;
            pull_through(json!({ "https_proxy": url, "no_proxy": no_proxy })).await;

            let seen = seen.lock().unwrap().clone();
            let expected = "CONNECT registry.example.invalid:443 HTTP/1.1";
            assert_eq!(!seen.is_empty(), proxied, "{seen:?}");
            assert!(seen.iter().all(|line| line == expected), "{seen:?}");
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

    #[test]
    fn load_rejects_settings_reqwest_would_ignore_or_misread() {
        assert_rejected(json!({ "https_proxy": "htp://p:3128" }), "https_proxy must");
        assert_rejected(json!({ "http_proxy": "p.corp:3128" }), "http_proxy must");
        assert_rejected(json!({ "https_proxy": "http://p:99999" }), "invalid port");
        assert_rejected(json!({ "no_proxy": "localhost" }), "no_proxy requires");
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
