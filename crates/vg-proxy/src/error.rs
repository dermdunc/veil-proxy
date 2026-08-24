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
    MaskRequest(#[from] crate::mask_request::MaskRequestError),
    #[error("failed to connect to upstream {addr}: {source}")]
    UpstreamConnect {
        addr: std::net::SocketAddr,
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
