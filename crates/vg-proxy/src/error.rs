use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error(
        "refusing to bind non-loopback address {addr} — M1 is loopback-only by design \
         (plan §10.3: \"Plain-HTTP hyper server on loopback\")"
    )]
    NotLoopback { addr: std::net::SocketAddr },
    #[error("failed to bind listener on {addr}: {source}")]
    Bind {
        addr: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("connection I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("vault error: {0}")]
    Vault(#[from] vg_core::VaultError),
    #[error("session resolution error: {0}")]
    Session(#[from] crate::session::SessionError),
    #[error("policy load error: {0}")]
    Policy(#[from] vg_core::PolicyError),
    #[error("audit log open error: {0}")]
    AuditOpen(#[from] vg_audit::OpenError),
    #[error("request masking error: {0}")]
    MaskRequest(#[from] crate::codec::MaskRequestError),
    #[error("failed to connect to upstream {host}:{port}: {source}")]
    UpstreamConnect {
        host: String,
        port: u16,
        #[source]
        source: std::io::Error,
    },
    // A2: real TLS client. `{host}` is not a valid DNS name for TLS SNI/hostname verification —
    // caught before ever attempting a handshake, distinct from a handshake that starts and then
    // fails (UpstreamTls below), which matters for diagnosing a bad UpstreamConfig vs. a bad
    // network/certificate.
    #[error("upstream host {host:?} is not a valid DNS name for TLS: {source}")]
    UpstreamInvalidServerName {
        host: String,
        #[source]
        source: rustls::pki_types::InvalidDnsNameError,
    },
    // Covers the real failure modes this milestone's own confirmation/disproof criteria care
    // about: an expired/untrusted/wrong-host certificate fails here, as a real `rustls` chain-
    // or hostname-verification error surfaced through `tokio_rustls`'s `io::Error` wrapping —
    // never silently downgraded to a generic I/O error a caller could mistake for a network
    // blip.
    #[error("TLS handshake with upstream {host} failed: {source}")]
    UpstreamTls {
        host: String,
        #[source]
        source: std::io::Error,
    },
    #[error("upstream connection handshake failed: {0}")]
    UpstreamHandshake(#[source] hyper::Error),
    #[error("failed to build upstream request: {0}")]
    UpstreamRequestBuild(#[source] hyper::http::Error),
    #[error("failed to send request to upstream: {0}")]
    UpstreamSend(#[source] hyper::Error),
    #[error("failed to read upstream response body: {0}")]
    UpstreamResponseBody(#[source] hyper::Error),
}
