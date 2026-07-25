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
}
