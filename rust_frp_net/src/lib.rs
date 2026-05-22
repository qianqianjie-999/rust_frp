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
use std::sync::Arc;
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::{server, client, TlsAcceptor, TlsConnector};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{accept_async, connect_async, WebSocketStream};
use futures_util::{Sink, Stream};
use std::io::BufReader;
use tokio_rustls::rustls::client::danger::{ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid};
use tokio_rustls::rustls::DigitallySignedStruct;
use tokio_rustls::rustls::Error as TlsError;
use tokio_rustls::rustls::SignatureScheme;
use tokio_rustls::rustls::pki_types::UnixTime;

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    Tls(#[from] tokio_rustls::rustls::Error),
    #[error("PEM decode error: {0}")]
    PemDecode(String),
    #[error("not a TLS server config")]
    NotServerConfig,
    #[error("not a TLS client config")]
    NotClientConfig,
    #[error("TLS config not set")]
    TlsConfigNotSet,
    #[error("{0}")]
    Other(String),
}

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

/// 实现 server::TlsStream<TokioTcpStream> 的 FrpConn trait
impl FrpConn for server::TlsStream<TokioTcpStream> {
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.get_ref().0.peer_addr().ok()
    }
}

/// 实现 client::TlsStream<TokioTcpStream> 的 FrpConn trait
impl FrpConn for client::TlsStream<TokioTcpStream> {
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.get_ref().0.peer_addr().ok()
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
        if !self.read_buf.is_empty() {
            let len = std::cmp::min(self.read_buf.len(), buf.remaining());
            buf.put_slice(&self.read_buf[..len]);
            self.read_buf.drain(..len);
            return std::task::Poll::Ready(Ok(()));
        }

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
                std::task::Poll::Ready(Err(std::io::Error::other(e)))
            }
            std::task::Poll::Ready(Some(Ok(_))) => {
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
                        std::task::Poll::Ready(Err(std::io::Error::other(e)))
                    }
                }
            }
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Err(std::io::Error::other(e)))
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
                std::task::Poll::Ready(Err(std::io::Error::other(e)))
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
                std::task::Poll::Ready(Err(std::io::Error::other(e)))
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

/// 跳过证书验证的结构体，用于客户端不验证服务器证书的场景
#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

/// TLS 配置
pub struct TlsConfig {
    server_config: Option<Arc<tokio_rustls::rustls::ServerConfig>>,
    client_config: Option<Arc<tokio_rustls::rustls::ClientConfig>>,
}

impl Clone for TlsConfig {
    fn clone(&self) -> Self {
        Self {
            server_config: self.server_config.clone(),
            client_config: self.client_config.clone(),
        }
    }
}

impl TlsConfig {
    /// 从文件创建服务器 TLS 配置
    pub fn new_server(cert_file: &str, key_file: &str) -> Result<Self, NetError> {
        let cert_file = std::fs::File::open(cert_file)?;
        let mut cert_reader = BufReader::new(cert_file);
        let cert_chain: Result<Vec<CertificateDer<'static>>, _> = rustls_pemfile::certs(&mut cert_reader)
            .collect();
        let cert_chain = cert_chain.map_err(|e| NetError::PemDecode(format!("{}", e)))?;

        let key_file_path = key_file.to_string();
        let key_file = std::fs::File::open(&key_file_path)?;
        let mut key_reader = BufReader::new(key_file);
        let pkcs8_keys: Result<Vec<_>, _> = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
            .collect();
        let mut keys: Vec<PrivateKeyDer<'static>> = pkcs8_keys.map_err(|e| NetError::PemDecode(format!("{}", e)))?.into_iter().map(|k| k.into()).collect();
        
        if keys.is_empty() {
            let key_file = std::fs::File::open(&key_file_path)?;
            let mut key_reader = BufReader::new(key_file);
            let rsa_keys: Result<Vec<_>, _> = rustls_pemfile::rsa_private_keys(&mut key_reader)
                .collect();
            let rsa_keys: Vec<PrivateKeyDer<'static>> = rsa_keys.map_err(|e| NetError::PemDecode(format!("{}", e)))?.into_iter().map(|k| k.into()).collect();
            keys.extend(rsa_keys);
        }
        
        if keys.is_empty() {
            return Err(NetError::Other("No private key found in file".to_string()));
        }
        let key = keys.remove(0);

        let config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?;

        Ok(Self {
            server_config: Some(Arc::new(config)),
            client_config: None,
        })
    }

    /// 创建客户端 TLS 配置，信任自定义 CA 证书文件
    pub fn new_client_with_ca_file(ca_file: &str) -> Result<Self, NetError> {
        let cert_file = std::fs::File::open(ca_file)?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs: Result<Vec<CertificateDer<'static>>, _> = rustls_pemfile::certs(&mut cert_reader)
            .collect();
        let certs = certs.map_err(|e| NetError::PemDecode(format!("{}", e)))?;

        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        for cert in certs {
            root_store.add(cert).map_err(|e| NetError::Tls(e))?;
        }

        let config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(Arc::new(root_store))
            .with_no_client_auth();

        Ok(Self {
            server_config: None,
            client_config: Some(Arc::new(config)),
        })
    }

    /// 创建客户端 TLS 配置（跳过证书验证）
    /// 仅使用 TLS 加密，但不验证服务器证书
    /// 类似于原版 frp 中没有 trustedCaFile 时的行为
    pub fn new_client_insecure() -> Result<Self, NetError> {
        let verifier = SkipServerVerification;
        let config = tokio_rustls::rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

        Ok(Self {
            server_config: None,
            client_config: Some(Arc::new(config)),
        })
    }

    /// 创建客户端 TLS 配置（使用系统根证书）
    pub fn new_client() -> Result<Self, NetError> {
        let root_certs: Vec<CertificateDer<'static>> = webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            CertificateDer::from(ta.subject_public_key_info.to_vec())
        }).collect();
        
        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        for cert in root_certs {
            root_store.add(cert).map_err(|e| NetError::Tls(e))?;
        }

        let config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(Arc::new(root_store))
            .with_no_client_auth();

        Ok(Self {
            server_config: None,
            client_config: Some(Arc::new(config)),
        })
    }

    /// 创建客户端 TLS 配置，信任内置自签名证书
    /// 将内置证书添加到 trust store 并启用证书验证
    pub fn new_client_trusting_builtin() -> Result<Self, NetError> {
        let cert_pem = include_bytes!("../cert/frp.crt");
        let certs: Result<Vec<CertificateDer<'static>>, _> = rustls_pemfile::certs(&mut &cert_pem[..])
            .collect();
        let certs = certs.map_err(|e| NetError::PemDecode(format!("{}", e)))?;
        
        let cert_der = certs.into_iter()
            .next()
            .ok_or_else(|| NetError::Other("No certificate found in builtin cert".to_string()))?;

        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        root_store.add(cert_der).map_err(|e| NetError::Tls(e))?;

        let config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(Arc::new(root_store))
            .with_no_client_auth();

        Ok(Self {
            server_config: None,
            client_config: Some(Arc::new(config)),
        })
    }

    /// 创建使用内置自签名证书的服务器 TLS 配置
    pub fn new_server_with_builtin_cert() -> Result<Self, NetError> {
        let cert_pem = include_bytes!("../cert/frp.crt");
        let key_pem = include_bytes!("../cert/frp.key");

        let certs: Result<Vec<CertificateDer<'static>>, _> = rustls_pemfile::certs(&mut &cert_pem[..])
            .collect();
        let cert_chain = certs.map_err(|e| NetError::PemDecode(format!("{}", e)))?;

        let pkcs8_keys: Result<Vec<_>, _> = rustls_pemfile::pkcs8_private_keys(&mut &key_pem[..])
            .collect();
        let mut keys: Vec<PrivateKeyDer<'static>> = pkcs8_keys.map_err(|e| NetError::PemDecode(format!("{}", e)))?.into_iter().map(|k| k.into()).collect();
        
        if keys.is_empty() {
            let rsa_keys: Result<Vec<_>, _> = rustls_pemfile::rsa_private_keys(&mut &key_pem[..])
                .collect();
            let rsa_keys: Vec<PrivateKeyDer<'static>> = rsa_keys.map_err(|e| NetError::PemDecode(format!("{}", e)))?.into_iter().map(|k| k.into()).collect();
            keys.extend(rsa_keys);
        }
        
        if keys.is_empty() {
            return Err(NetError::Other("No private key found in builtin cert".to_string()));
        }
        let key = keys.remove(0);

        let config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?;

        Ok(Self {
            server_config: Some(Arc::new(config)),
            client_config: None,
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

    pub async fn accept(&self, stream: TokioTcpStream) -> Result<server::TlsStream<TokioTcpStream>, std::io::Error> {
        if let Some(config) = &self.server_config {
            let acceptor = TlsAcceptor::from(config.clone());
            acceptor.accept(stream).await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a server config",
            ))
        }
    }

    pub async fn connect(&self, domain: &str, stream: TokioTcpStream) -> Result<client::TlsStream<TokioTcpStream>, std::io::Error> {
        if let Some(config) = &self.client_config {
            let server_name = ServerName::try_from(domain.to_string())
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid server name"))?;
            let connector = TlsConnector::from(config.clone());
            connector.connect(server_name, stream).await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
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

    pub async fn connect_tls(&self, domain: &str, addr: &SocketAddr) -> Result<client::TlsStream<TokioTcpStream>, std::io::Error> {
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
            std::io::Error::other(e)
        })?;
        let remote_addr = "127.0.0.1:0".parse().unwrap();
        Ok(WebSocketConn::new(stream, remote_addr))
    }

    pub async fn accept_websocket(&self, stream: TokioTcpStream) -> Result<WebSocketConn<TokioTcpStream>, std::io::Error> {
        let remote_addr = stream.peer_addr()?;
        let stream = accept_async(stream).await.map_err(|e| {
            std::io::Error::other(e)
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
