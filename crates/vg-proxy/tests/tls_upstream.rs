//! A2's own confirmation criteria (INT-2026-09-13-001, post-Codex-critique): "real TLS" means
//! standard WebPKI certificate chain validation and hostname matching, with no disabled or
//! bypassed verification. These tests prove `vg_proxy::upstream::forward` genuinely enforces
//! that against a real local TLS server, not just that it can open an encrypted socket:
//!
//! - a certificate signed by a CA the client trusts, for the hostname the client actually
//!   dials, succeeds — the same code path `UpstreamConfig::real_anthropic()` uses in production,
//!   with a locally-generated trust root substituted for the real Mozilla set so the test
//!   doesn't depend on any live network or real CA.
//! - a certificate signed by that same trusted CA, but for the WRONG hostname, is refused —
//!   proves hostname verification is real, not merely chain validation.
//! - a certificate that is not signed by any CA the client trusts at all (a second,
//!   independently-generated CA) is refused — proves chain validation is real.
//!
//! All three servers speak real HTTP/1.1 once (if ever) the TLS handshake completes, so a test
//! that unexpectedly succeeds fails on a real, observable HTTP response rather than a
//! connection-shape assumption.

use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use vg_proxy::error::ProxyError;
use vg_proxy::upstream::{self, UpstreamConfig};

/// One self-signed CA plus one leaf certificate signed by it, for `leaf_hostname`. Returns the
/// CA's own DER (for building a client config that trusts it) and a `rustls::ServerConfig`
/// presenting the leaf.
fn make_ca_and_leaf(leaf_hostname: &str) -> (CertificateDer<'static>, Arc<ServerConfig>) {
    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).expect("empty SAN list is valid for a CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().expect("generate CA key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA cert");

    let leaf_params =
        CertificateParams::new(vec![leaf_hostname.to_string()]).expect("leaf SAN list");
    let leaf_key = KeyPair::generate().expect("generate leaf key");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("sign leaf cert with test CA");

    let leaf_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![leaf_cert.der().clone()], leaf_key_der)
        .expect("build server TLS config from the leaf cert");

    (ca_cert.der().clone(), Arc::new(server_config))
}

/// A `ClientConfig` trusting exactly `trusted_ca`, nothing else — the local-test equivalent of
/// `UpstreamConfig::real_anthropic()`'s `webpki-roots`-backed config, with one generated CA
/// substituted for the real Mozilla root set.
fn client_config_trusting(trusted_ca: &CertificateDer<'static>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(trusted_ca.clone())
        .expect("add test CA to root store");
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Accepts exactly one TLS connection on an OS-assigned loopback port, serves it as real
/// HTTP/1.1 with a fixed 200 response, then stops. Returns the port to connect to and the
/// server's join handle (awaited by callers that expect the handshake to succeed; callers that
/// expect the handshake to fail don't need to await it — the task simply never completes its
/// accept, which is fine, it's dropped with the runtime at test end).
async fn spawn_https_server(tls_config: Arc<ServerConfig>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test TLS server");
    let port = listener.local_addr().expect("local addr").port();
    let acceptor = TlsAcceptor::from(tls_config);

    tokio::spawn(async move {
        let Ok((tcp, _peer)) = listener.accept().await else {
            return;
        };
        let Ok(tls_stream) = acceptor.accept(tcp).await else {
            // Expected for the two "must reject" tests: the client aborts the handshake before
            // it completes, so the server-side accept() also errors. Nothing to serve.
            return;
        };
        let io = TokioIo::new(tls_stream);
        let service = service_fn(|_req: Request<hyper::body::Incoming>| async {
            Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::from_static(b"{\"ok\":true}")))
                    .expect("static response is well-formed"),
            )
        });
        let _ = server_http1::Builder::new()
            .serve_connection(io, service)
            .await;
    });

    port
}

/// The happy path: a certificate signed by a trusted CA, for the hostname the client actually
/// dials — `forward()` succeeds and returns the real 200 response.
#[tokio::test]
async fn accepts_a_certificate_signed_by_a_trusted_ca_for_the_right_hostname() {
    let (ca_der, server_config) = make_ca_and_leaf("localhost");
    let port = spawn_https_server(server_config).await;
    let client_config = client_config_trusting(&ca_der);

    let upstream = UpstreamConfig::tls("localhost", port, client_config);
    let resp = upstream::forward(upstream, Method::GET, "/", &HeaderMap::new(), Vec::new())
        .await
        .expect("a validly-signed, right-hostname certificate must be accepted");

    assert_eq!(resp.status(), StatusCode::OK);
}

/// Hostname verification is real: a certificate signed by a CA the client trusts, but issued
/// for a DIFFERENT hostname than the one the client dials, must be refused — proves this isn't
/// merely "chain validation with the hostname check silently skipped."
#[tokio::test]
async fn refuses_a_certificate_signed_by_a_trusted_ca_for_the_wrong_hostname() {
    let (ca_der, server_config) = make_ca_and_leaf("not-the-host-we-dial.example");
    let port = spawn_https_server(server_config).await;
    let client_config = client_config_trusting(&ca_der);

    // The client dials "localhost", but the presented certificate is only valid for
    // "not-the-host-we-dial.example" — same trusted CA, wrong name.
    let upstream = UpstreamConfig::tls("localhost", port, client_config);
    let err = upstream::forward(upstream, Method::GET, "/", &HeaderMap::new(), Vec::new())
        .await
        .expect_err("a right-CA, wrong-hostname certificate must be refused");

    assert!(
        matches!(err, ProxyError::UpstreamTls { .. }),
        "expected a TLS handshake failure, got: {err:?}"
    );
}

/// Chain validation is real: a certificate that is well-formed and for the right hostname, but
/// signed by a CA the client does NOT trust, must be refused.
#[tokio::test]
async fn refuses_a_certificate_signed_by_an_untrusted_ca() {
    let (_untrusted_ca_der, server_config) = make_ca_and_leaf("localhost");
    let port = spawn_https_server(server_config).await;

    // A second, independently-generated CA — the client trusts THIS one, not the one that
    // actually signed the server's certificate above.
    let (other_ca_der, _unused_server_config) = make_ca_and_leaf("localhost");
    let client_config = client_config_trusting(&other_ca_der);

    let upstream = UpstreamConfig::tls("localhost", port, client_config);
    let err = upstream::forward(upstream, Method::GET, "/", &HeaderMap::new(), Vec::new())
        .await
        .expect_err("a certificate signed by an untrusted CA must be refused");

    assert!(
        matches!(err, ProxyError::UpstreamTls { .. }),
        "expected a TLS handshake failure, got: {err:?}"
    );
}
