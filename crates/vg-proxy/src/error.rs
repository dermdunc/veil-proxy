use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("failed to bind listener on {addr}: {source}")]
    Bind {
        addr: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("connection I/O error: {0}")]
    Io(#[from] std::io::Error),
}
