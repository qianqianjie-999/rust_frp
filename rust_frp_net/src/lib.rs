use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio_openssl::SslStream;
use openssl::ssl::{SslContext, SslAcceptor, SslConnector};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{accept_async, connect_async, WebSocketStream};
use futures_util::{SinkExt, StreamExt};

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
pub struct WebSocketConn {
    stream: WebSocketStream<TokioTcpStream>,
    remote_addr: SocketAddr,
    read_buf: Vec<u8>,
}

impl WebSocketConn {
    pub fn new(stream: WebSocketStream<TokioTcpStream>, remote_addr: SocketAddr) -> Self {
        Self {
            stream,
            remote_addr,
            read_buf: Vec::new(),
        }
    }
}

impl AsyncRead for WebSocketConn {
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

impl AsyncWrite for WebSocketConn {
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

impl FrpConn for WebSocketConn {
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
    acceptor: Option<SslAcceptor>,
    connector: Option<SslConnector>,
}

impl TlsConfig {
    /// 从文件创建服务器 TLS 配置
    pub fn new_server(cert_file: &str, key_file: &str) -> Result<Self, openssl::error::ErrorStack> {
        let mut builder = SslAcceptor::mozilla_intermediate(openssl::ssl::SslMethod::tls())?;
        builder.set_certificate_file(cert_file, openssl::ssl::SslFiletype::PEM)?;
        builder.set_private_key_file(key_file, openssl::ssl::SslFiletype::PEM)?;
        Ok(Self {
            acceptor: Some(builder.build()),
            connector: None,
        })
    }

    /// 创建客户端 TLS 配置
    pub fn new_client() -> Result<Self, openssl::error::ErrorStack> {
        let builder = SslConnector::mozilla_intermediate(openssl::ssl::SslMethod::tls())?;
        Ok(Self {
            acceptor: None,
            connector: Some(builder.build()),
        })
    }

    /// 创建使用内置自签名证书的服务器 TLS 配置
    pub fn new_server_with_builtin_cert() -> Result<Self, openssl::error::ErrorStack> {
        // 内置自签名证书
        let cert_pem = include_bytes!("../cert/frp.crt");
        let key_pem = include_bytes!("../cert/frp.key");

        let mut builder = SslAcceptor::mozilla_intermediate(openssl::ssl::SslMethod::tls())?;
        builder.set_certificate(&openssl::x509::X509::from_pem(cert_pem)?)?;
        builder.set_private_key(&openssl::pkey::PKey::private_key_from_pem(key_pem)?)?;
        Ok(Self {
            acceptor: Some(builder.build()),
            connector: None,
        })
    }

    pub async fn accept(&self, stream: TokioTcpStream) -> Result<SslStream<TokioTcpStream>, std::io::Error> {
        if let Some(acceptor) = &self.acceptor {
            let stream = tokio_openssl::accept(acceptor, stream).await?;
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
            let stream = tokio_openssl::connect(connector, domain, stream).await?;
            Ok(stream)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a client config",
            ))
        }
    }
}

/// 连接池
pub struct ConnPool {
    conns: Vec<TokioTcpStream>,
    addr: SocketAddr,
    max_size: usize,
}

impl ConnPool {
    pub fn new(addr: SocketAddr, max_size: usize) -> Self {
        Self {
            conns: Vec::with_capacity(max_size),
            addr,
            max_size,
        }
    }

    pub async fn get(&mut self) -> Result<TokioTcpStream, std::io::Error> {
        if let Some(conn) = self.conns.pop() {
            Ok(conn)
        } else {
            TokioTcpStream::connect(&self.addr).await
        }
    }

    pub fn put(&mut self, conn: TokioTcpStream) {
        if self.conns.len() < self.max_size {
            self.conns.push(conn);
        }
    }
}

/// 网络连接管理器
pub struct ConnManager {
    tls_config: Option<TlsConfig>,
    conn_pools: std::collections::HashMap<SocketAddr, ConnPool>,
    max_pool_size: usize,
}

impl ConnManager {
    pub fn new(tls_config: Option<TlsConfig>, max_pool_size: usize) -> Self {
        Self {
            tls_config,
            conn_pools: std::collections::HashMap::new(),
            max_pool_size,
        }
    }

    pub async fn connect_tcp(&mut self, addr: &SocketAddr) -> Result<TokioTcpStream, std::io::Error> {
        let pool = self.conn_pools.entry(*addr).or_insert_with(|| {
            ConnPool::new(*addr, self.max_pool_size)
        });
        pool.get().await
    }

    pub async fn connect_tls(&mut self, domain: &str, addr: &SocketAddr) -> Result<SslStream<TokioTcpStream>, std::io::Error> {
        let stream = self.connect_tcp(addr).await?;
        if let Some(tls_config) = &self.tls_config {
            tls_config.connect(domain, stream).await
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TLS config not set",
            ))
        }
    }

    pub async fn connect_websocket(&mut self, url: &str) -> Result<WebSocketConn, std::io::Error> {
        let (stream, _) = connect_async(url).await.map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })?;
        let remote_addr = "127.0.0.1:0".parse().unwrap(); // TODO: 从连接中获取实际的远程地址
        Ok(WebSocketConn::new(stream, remote_addr))
    }

    pub async fn accept_websocket(&self, stream: TokioTcpStream) -> Result<WebSocketConn, std::io::Error> {
        let remote_addr = stream.peer_addr()?;
        let stream = accept_async(stream).await.map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })?;
        Ok(WebSocketConn::new(stream, remote_addr))
    }

    pub fn put_back(&mut self, addr: SocketAddr, conn: TokioTcpStream) {
        if let Some(pool) = self.conn_pools.get_mut(&addr) {
            pool.put(conn);
        }
    }
}
