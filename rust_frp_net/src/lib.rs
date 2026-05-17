//! FRP 网络层模块
//!
//! 该模块提供了 FRP (Fast Reverse Proxy) 的核心网络抽象，包括：
//!
//! ## 主要组件
//!
//! 1. **连接抽象 (FrpConn trait)**
//!    - 统一的异步 I/O 接口，支持 TCP、TLS、WebSocket 等多种连接类型
//!    - 实现了 `AsyncRead` 和 `AsyncWrite` trait，便于数据流操作
//!
//! 2. **TLS 加密支持**
//!    - 支持自定义证书和内置自签名证书
//!    - 客户端可配置为信任内置证书，简化部署
//!
//! 3. **WebSocket 支持**
//!    - 支持通过 WebSocket 协议进行连接，适用于复杂网络环境
//!
//! 4. **连接池管理**
//!    - 支持 TCP 连接复用，减少连接建立开销
//!    - 支持连接池配置（大小、超时、空闲时间等）
//!
//! ## 安全性
//!
//! - TLS 1.2 及以上版本
//! - 内置自签名证书，方便快速部署
//! - 支持自定义证书，可用于生产环境

use std::net::SocketAddr;
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_openssl::SslStream;
use openssl::ssl::{SslContext, SslVerifyMode};
use openssl::x509::X509;
use openssl::pkey::PKey;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{accept_async, connect_async, WebSocketStream};
use futures_util::{Sink, Stream};

/// 网络连接 trait
#[async_trait::async_trait]
pub trait FrpConn: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {
    fn remote_addr(&self) -> Option<SocketAddr>;
}

/// 实现 TokioTcpStream 的 FrpConn trait
impl FrpConn for TokioTcpStream {
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.peer_addr().ok()
    }
}

/// 实现 SslStream<TokioTcpStream> 的 FrpConn trait
impl FrpConn for SslStream<TokioTcpStream> {
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.get_ref().peer_addr().ok()
    }
}

/// WebSocket 连接
pub struct WebSocketConn<S> {
    stream: WebSocketStream<S>,
    remote_addr: SocketAddr,
    read_buf: Vec<u8>,
}

impl<S> WebSocketConn<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: WebSocketStream<S>, remote_addr: SocketAddr) -> Self {
        Self {
            stream,
            remote_addr,
            read_buf: Vec::new(),
        }
    }
}

impl<S> AsyncRead for WebSocketConn<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // 首先检查 read_buf 中是否有数据
        if !self.read_buf.is_empty() {
            let len = std::cmp::min(self.read_buf.len(), buf.remaining());
            buf.put_slice(&self.read_buf[..len]);
            self.read_buf.drain(..len);
            return std::task::Poll::Ready(Ok(()));
        }

        // 从 WebSocket 流中读取数据
        match std::pin::Pin::new(&mut self.stream).poll_next(cx) {
            std::task::Poll::Ready(Some(Ok(WsMessage::Binary(data)))) => {
                let len = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..len]);
                if len < data.len() {
                    self.read_buf.extend_from_slice(&data[len..]);
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Some(Ok(WsMessage::Text(text)))) => {
                let data = text.as_bytes();
                let len = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..len]);
                if len < data.len() {
                    self.read_buf.extend_from_slice(&data[len..]);
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Some(Err(e))) => {
                std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e,
                )))
            }
            std::task::Poll::Ready(Some(Ok(_))) => {
                // 忽略其他类型的消息
                self.poll_read(cx, buf)
            }
            std::task::Poll::Ready(None) => {
                std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "websocket closed",
                )))
            }
            std::task::Poll::Pending => {
                std::task::Poll::Pending
            }
        }
    }
}

impl<S> AsyncWrite for WebSocketConn<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let msg = WsMessage::Binary(buf.to_vec());
        match std::pin::Pin::new(&mut self.stream).poll_ready(cx) {
            std::task::Poll::Ready(Ok(())) => {
                match std::pin::Pin::new(&mut self.stream).start_send(msg) {
                    Ok(_) => {
                        std::task::Poll::Ready(Ok(buf.len()))
                    }
                    Err(e) => {
                        std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            e,
                        )))
                    }
                }
            }
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e,
                )))
            }
            std::task::Poll::Pending => {
                std::task::Poll::Pending
            }
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::new(&mut self.stream).poll_flush(cx) {
            std::task::Poll::Ready(Ok(())) => {
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e,
                )))
            }
            std::task::Poll::Pending => {
                std::task::Poll::Pending
            }
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::new(&mut self.stream).poll_close(cx) {
            std::task::Poll::Ready(Ok(())) => {
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e,
                )))
            }
            std::task::Poll::Pending => {
                std::task::Poll::Pending
            }
        }
    }
}

impl<S> FrpConn for WebSocketConn<S>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote_addr)
    }
}

/// TCP 监听器
pub struct TcpListener {
    inner: TokioTcpListener,
}

impl TcpListener {
    pub async fn bind(addr: &SocketAddr) -> Result<Self, std::io::Error> {
        let inner = TokioTcpListener::bind(addr).await?;
        Ok(Self { inner })
    }

    pub async fn accept(&self) -> Result<(TokioTcpStream, SocketAddr), std::io::Error> {
        self.inner.accept().await
    }
}

/// UDP 监听器
pub struct UdpListener {
    inner: TokioUdpSocket,
}

impl UdpListener {
    pub async fn bind(addr: &SocketAddr) -> Result<Self, std::io::Error> {
        let inner = TokioUdpSocket::bind(addr).await?;
        Ok(Self { inner })
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), std::io::Error> {
        self.inner.recv_from(buf).await
    }

    pub async fn send_to(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize, std::io::Error> {
        self.inner.send_to(buf, addr).await
    }
}

/// TLS 配置
pub struct TlsConfig {
    acceptor: Option<openssl::ssl::SslContext>,
    connector: Option<openssl::ssl::SslContext>,
}

impl Clone for TlsConfig {
    fn clone(&self) -> Self {
        Self {
            acceptor: self.acceptor.clone(),
            connector: self.connector.clone(),
        }
    }
}

impl TlsConfig {
    /// 从文件创建服务器 TLS 配置
    pub fn new_server(cert_file: &str, key_file: &str) -> Result<Self, openssl::error::ErrorStack> {
        let mut ctx = SslContext::builder(openssl::ssl::SslMethod::tls_server())?;
        ctx.set_certificate_file(cert_file, openssl::ssl::SslFiletype::PEM)?;
        ctx.set_private_key_file(key_file, openssl::ssl::SslFiletype::PEM)?;
        Ok(Self {
            acceptor: Some(ctx.build()),
            connector: None,
        })
    }

    /// 创建客户端 TLS 配置
    pub fn new_client() -> Result<Self, openssl::error::ErrorStack> {
        let mut ctx = SslContext::builder(openssl::ssl::SslMethod::tls_client())?;
        ctx.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))?;
        Ok(Self {
            acceptor: None,
            connector: Some(ctx.build()),
        })
    }

    /// 创建客户端 TLS 配置，信任内置自签名证书
    /// 将内置证书添加到 trust store 并启用证书验证
    pub fn new_client_trusting_builtin() -> Result<Self, openssl::error::ErrorStack> {
        let mut ctx = SslContext::builder(openssl::ssl::SslMethod::tls_client())?;
        ctx.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))?;

        let cert_pem = include_bytes!("../cert/frp.crt");
        let cert = X509::from_pem(cert_pem)?;
        ctx.cert_store_mut().add_cert(cert)?;
        ctx.set_verify(SslVerifyMode::PEER);

        Ok(Self {
            acceptor: None,
            connector: Some(ctx.build()),
        })
    }

    /// 创建使用内置自签名证书的服务器 TLS 配置
    pub fn new_server_with_builtin_cert() -> Result<Self, openssl::error::ErrorStack> {
        // 内置自签名证书
        let cert_pem = include_bytes!("../cert/frp.crt");
        let key_pem = include_bytes!("../cert/frp.key");

        let mut ctx = SslContext::builder(openssl::ssl::SslMethod::tls_server())?;
        ctx.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))?;
        let cert = X509::from_pem(cert_pem)?;
        ctx.set_certificate(&cert)?;
        let key = PKey::private_key_from_pem(key_pem)?;
        ctx.set_private_key(&key)?;
        Ok(Self {
            acceptor: Some(ctx.build()),
            connector: None,
        })
    }

    /// 获取内置证书的 PEM 数据（用于 Web 服务器 HTTPS）
    pub fn get_builtin_cert_pem() -> &'static [u8] {
        include_bytes!("../cert/frp.crt")
    }

    /// 获取内置私钥的 PEM 数据（用于 Web 服务器 HTTPS）
    pub fn get_builtin_key_pem() -> &'static [u8] {
        include_bytes!("../cert/frp.key")
    }

    pub async fn accept(&self, stream: TokioTcpStream) -> Result<SslStream<TokioTcpStream>, std::io::Error> {
        if let Some(acceptor) = &self.acceptor {
            let ssl = openssl::ssl::Ssl::new(acceptor)?;
            let mut stream = SslStream::new(ssl, stream)?;
            std::pin::Pin::new(&mut stream).accept().await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            Ok(stream)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a server config",
            ))
        }
    }

    pub async fn connect(&self, domain: &str, stream: TokioTcpStream) -> Result<SslStream<TokioTcpStream>, std::io::Error> {
        if let Some(connector) = &self.connector {
            let mut ssl = openssl::ssl::Ssl::new(connector)?;
            ssl.set_hostname(domain)?;
            let mut stream = SslStream::new(ssl, stream)?;
            std::pin::Pin::new(&mut stream).connect().await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            Ok(stream)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a client config",
            ))
        }
    }
}



/// 网络连接管理器
pub struct ConnManager {
    pub tls_config: Option<TlsConfig>,
    pool_manager: PoolManager,
}

impl ConnManager {
    pub fn new(tls_config: Option<TlsConfig>, max_pool_size: usize) -> Self {
        let pool_config = PoolConfig {
            max_size: max_pool_size,
            ..Default::default()
        };
        
        Self {
            tls_config,
            pool_manager: PoolManager::new(pool_config),
        }
    }

    pub async fn connect_tcp(&self, addr: &SocketAddr) -> Result<PooledConn, std::io::Error> {
        let pool = self.pool_manager.get_or_create_pool(*addr).await;
        pool.get().await
    }

    pub async fn connect_tls(&self, domain: &str, addr: &SocketAddr) -> Result<SslStream<TokioTcpStream>, std::io::Error> {
        let pooled = self.connect_tcp(addr).await?;
        if let Some(tls_config) = &self.tls_config {
            tls_config.connect(domain, pooled.conn).await
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TLS config not set",
            ))
        }
    }

    pub async fn connect_websocket(&self, url: &str) -> Result<WebSocketConn<tokio_tungstenite::MaybeTlsStream<TokioTcpStream>>, std::io::Error> {
        let (stream, _) = connect_async(url).await.map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })?;
        let remote_addr = "127.0.0.1:0".parse().unwrap(); // TODO: 从连接中获取实际的远程地址
        Ok(WebSocketConn::new(stream, remote_addr))
    }

    pub async fn accept_websocket(&self, stream: TokioTcpStream) -> Result<WebSocketConn<TokioTcpStream>, std::io::Error> {
        let remote_addr = stream.peer_addr()?;
        let stream = accept_async(stream).await.map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })?;
        Ok(WebSocketConn::new(stream, remote_addr))
    }

    pub async fn put_back(&self, addr: SocketAddr, conn: PooledConn) {
        if let Some(pool) = self.pool_manager.get_pool(addr).await {
            pool.put(conn).await;
        }
    }

    pub fn get_tls_config(&self) -> Option<&TlsConfig> {
        self.tls_config.as_ref()
    }

    pub fn get_pool_manager(&self) -> &PoolManager {
        &self.pool_manager
    }
}

// 导出连接池模块
pub mod pool;

// 重新导出连接池类型
pub use pool::{ConnPool, PoolManager, PoolConfig, PoolStats, PooledConn};
