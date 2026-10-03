//! 服务端错误类型

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("proxy not found: {0}")]
    ProxyNotFound(String),
    #[error("port not allowed: {0}")]
    PortNotAllowed(u16),
    #[error("proxy already exists: {0}")]
    ProxyAlreadyExists(String),
    #[error("work conn request timeout")]
    WorkConnTimeout,
    #[error("run ID mismatch")]
    RunIdMismatch,
    #[error("{0}")]
    Other(String),
}
