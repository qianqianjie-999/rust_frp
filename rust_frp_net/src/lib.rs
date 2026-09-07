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

use futures_util::{Sink, Stream};
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{
    TcpListener as TokioTcpListener, TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket,
};
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::UnixTime;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::DigitallySignedStruct;
use tokio_rustls::rustls::Error as TlsError;
use tokio_rustls::rustls::SignatureScheme;
use tokio_rustls::{client, server, TlsAcceptor, TlsConnector};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{accept_async, connect_async, WebSocketStream};

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

/// 类型擦除的连接（TCP/TLS/KCP/WebSocket 统一类型）
///
/// `Box<dyn FrpConn>` 自动满足 AsyncRead + AsyncWrite + Unpin + Send，
/// 可直接用于消息读写与 bridge_streams 桥接。
pub type AnyConn = Box<dyn FrpConn>;

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
    /// 创建新的 WebSocket 连接
    ///
    /// # 参数
    ///
    /// * `stream` - WebSocket 流
    /// * `remote_addr` - 远程地址
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
            std::task::Poll::Ready(Some(Ok(_))) => self.poll_read(cx, buf),
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "websocket closed",
            ))),
            std::task::Poll::Pending => std::task::Poll::Pending,
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
                    Ok(_) => std::task::Poll::Ready(Ok(buf.len())),
                    Err(e) => std::task::Poll::Ready(Err(std::io::Error::other(e))),
                }
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(std::io::Error::other(e))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::new(&mut self.stream).poll_flush(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(std::io::Error::other(e))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::new(&mut self.stream).poll_close(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(std::io::Error::other(e))),
            std::task::Poll::Pending => std::task::Poll::Pending,
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
    /// 绑定到指定地址
    ///
    /// # 参数
    ///
    /// * `addr` - 要绑定的地址
    pub async fn bind(addr: &SocketAddr) -> Result<Self, std::io::Error> {
        let inner = TokioTcpListener::bind(addr).await?;
        Ok(Self { inner })
    }

    /// 接受一个新连接
    pub async fn accept(&self) -> Result<(TokioTcpStream, SocketAddr), std::io::Error> {
        self.inner.accept().await
    }
}

/// UDP 监听器
pub struct UdpListener {
    inner: TokioUdpSocket,
}

impl UdpListener {
    /// 绑定到指定地址
    ///
    /// # 参数
    ///
    /// * `addr` - 要绑定的地址
    pub async fn bind(addr: &SocketAddr) -> Result<Self, std::io::Error> {
        let inner = TokioUdpSocket::bind(addr).await?;
        Ok(Self { inner })
    }

    /// 从远程地址接收数据
    ///
    /// # 参数
    ///
    /// * `buf` - 接收数据的缓冲区
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), std::io::Error> {
        self.inner.recv_from(buf).await
    }

    /// 发送数据到指定地址
    ///
    /// # 参数
    ///
    /// * `buf` - 要发送的数据
    /// * `addr` - 目标地址
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
        let cert_chain: Result<Vec<CertificateDer<'static>>, _> =
            rustls_pemfile::certs(&mut cert_reader).collect();
        let cert_chain = cert_chain.map_err(|e| NetError::PemDecode(format!("{}", e)))?;

        let key_file_path = key_file.to_string();
        let key_file = std::fs::File::open(&key_file_path)?;
        let mut key_reader = BufReader::new(key_file);
        let pkcs8_keys: Result<Vec<_>, _> =
            rustls_pemfile::pkcs8_private_keys(&mut key_reader).collect();
        let mut keys: Vec<PrivateKeyDer<'static>> = pkcs8_keys
            .map_err(|e| NetError::PemDecode(format!("{}", e)))?
            .into_iter()
            .map(|k| k.into())
            .collect();

        if keys.is_empty() {
            let key_file = std::fs::File::open(&key_file_path)?;
            let mut key_reader = BufReader::new(key_file);
            let rsa_keys: Result<Vec<_>, _> =
                rustls_pemfile::rsa_private_keys(&mut key_reader).collect();
            let rsa_keys: Vec<PrivateKeyDer<'static>> = rsa_keys
                .map_err(|e| NetError::PemDecode(format!("{}", e)))?
                .into_iter()
                .map(|k| k.into())
                .collect();
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
        let certs: Result<Vec<CertificateDer<'static>>, _> =
            rustls_pemfile::certs(&mut cert_reader).collect();
        let certs = certs.map_err(|e| NetError::PemDecode(format!("{}", e)))?;

        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        for cert in certs {
            root_store.add(cert).map_err(NetError::Tls)?;
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
        let root_certs: Vec<CertificateDer<'static>> = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .map(|ta| CertificateDer::from(ta.subject_public_key_info.to_vec()))
            .collect();

        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        for cert in root_certs {
            root_store.add(cert).map_err(NetError::Tls)?;
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
        let certs: Result<Vec<CertificateDer<'static>>, _> =
            rustls_pemfile::certs(&mut &cert_pem[..]).collect();
        let certs = certs.map_err(|e| NetError::PemDecode(format!("{}", e)))?;

        let cert_der = certs
            .into_iter()
            .next()
            .ok_or_else(|| NetError::Other("No certificate found in builtin cert".to_string()))?;

        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        root_store.add(cert_der).map_err(NetError::Tls)?;

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

        let certs: Result<Vec<CertificateDer<'static>>, _> =
            rustls_pemfile::certs(&mut &cert_pem[..]).collect();
        let cert_chain = certs.map_err(|e| NetError::PemDecode(format!("{}", e)))?;

        let pkcs8_keys: Result<Vec<_>, _> =
            rustls_pemfile::pkcs8_private_keys(&mut &key_pem[..]).collect();
        let mut keys: Vec<PrivateKeyDer<'static>> = pkcs8_keys
            .map_err(|e| NetError::PemDecode(format!("{}", e)))?
            .into_iter()
            .map(|k| k.into())
            .collect();

        if keys.is_empty() {
            let rsa_keys: Result<Vec<_>, _> =
                rustls_pemfile::rsa_private_keys(&mut &key_pem[..]).collect();
            let rsa_keys: Vec<PrivateKeyDer<'static>> = rsa_keys
                .map_err(|e| NetError::PemDecode(format!("{}", e)))?
                .into_iter()
                .map(|k| k.into())
                .collect();
            keys.extend(rsa_keys);
        }

        if keys.is_empty() {
            return Err(NetError::Other(
                "No private key found in builtin cert".to_string(),
            ));
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

    /// 接受 TLS 连接（服务端）
    ///
    /// # 参数
    ///
    /// * `stream` - 底层 TCP 流
    pub async fn accept(
        &self,
        stream: TokioTcpStream,
    ) -> Result<server::TlsStream<TokioTcpStream>, std::io::Error> {
        if let Some(config) = &self.server_config {
            let acceptor = TlsAcceptor::from(config.clone());
            acceptor.accept(stream).await.map_err(std::io::Error::other)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a server config",
            ))
        }
    }

    /// 建立 TLS 连接（客户端）
    ///
    /// # 参数
    ///
    /// * `domain` - 服务器域名
    /// * `stream` - 底层 TCP 流
    pub async fn connect(
        &self,
        domain: &str,
        stream: TokioTcpStream,
    ) -> Result<client::TlsStream<TokioTcpStream>, std::io::Error> {
        if let Some(config) = &self.client_config {
            let server_name = ServerName::try_from(domain.to_string()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid server name")
            })?;
            let connector = TlsConnector::from(config.clone());
            connector
                .connect(server_name, stream)
                .await
                .map_err(std::io::Error::other)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a client config",
            ))
        }
    }

    /// 接受 TLS 连接（泛型底层流）
    ///
    /// 与 [`TlsConfig::accept`] 相同，但底层流不限于 `TcpStream`，
    /// 供插件（任意访客连接）与多路复用（yamux 流上的 TLS）使用。
    pub async fn accept_stream<S>(&self, stream: S) -> Result<server::TlsStream<S>, std::io::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if let Some(config) = &self.server_config {
            let acceptor = TlsAcceptor::from(config.clone());
            acceptor.accept(stream).await.map_err(std::io::Error::other)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a server config",
            ))
        }
    }

    /// 建立 TLS 连接（泛型底层流）
    ///
    /// 与 [`TlsConfig::connect`] 相同，但底层流不限于 `TcpStream`，
    /// 供插件与多路复用（yamux 流上的 TLS）使用。
    pub async fn connect_stream<S>(
        &self,
        domain: &str,
        stream: S,
    ) -> Result<client::TlsStream<S>, std::io::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if let Some(config) = &self.client_config {
            let server_name = ServerName::try_from(domain.to_string()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid server name")
            })?;
            let connector = TlsConnector::from(config.clone());
            connector
                .connect(server_name, stream)
                .await
                .map_err(std::io::Error::other)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a client config",
            ))
        }
    }
}

/// 网络连接管理器
///
/// 统一管理所有网络连接，包括 TCP、TLS、WebSocket 和 KCP 连接。
pub struct ConnManager {
    /// TLS 配置
    pub tls_config: Option<TlsConfig>,
    pool_manager: PoolManager,
}

impl ConnManager {
    /// 创建新的连接管理器
    ///
    /// # 参数
    ///
    /// * `tls_config` - TLS 配置
    /// * `max_pool_size` - 连接池最大大小
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

    /// 建立 TCP 连接（使用连接池）
    ///
    /// # 参数
    ///
    /// * `addr` - 目标地址
    pub async fn connect_tcp(&self, addr: &SocketAddr) -> Result<PooledConn, std::io::Error> {
        let pool = self.pool_manager.get_or_create_pool(*addr).await;
        pool.get().await
    }

    /// 建立 TLS 连接（使用连接池）
    ///
    /// # 参数
    ///
    /// * `domain` - 服务器域名
    /// * `addr` - 目标地址
    pub async fn connect_tls(
        &self,
        domain: &str,
        addr: &SocketAddr,
    ) -> Result<client::TlsStream<TokioTcpStream>, std::io::Error> {
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

    /// 建立 WebSocket 连接
    ///
    /// # 参数
    ///
    /// * `url` - WebSocket 服务地址
    pub async fn connect_websocket(
        &self,
        url: &str,
    ) -> Result<WebSocketConn<tokio_tungstenite::MaybeTlsStream<TokioTcpStream>>, std::io::Error>
    {
        let (stream, _) = connect_async(url)
            .await
            .map_err(|e| std::io::Error::other(e))?;
        let remote_addr = "127.0.0.1:0".parse().unwrap();
        Ok(WebSocketConn::new(stream, remote_addr))
    }

    /// 建立 KCP 连接
    ///
    /// # 参数
    ///
    /// * `addr` - 目标地址
    pub async fn connect_kcp(&self, addr: &SocketAddr) -> Result<KcpConn, NetError> {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(NetError::Io)?;
        socket.connect(addr).await.map_err(NetError::Io)?;
        let socket = std::sync::Arc::new(socket);
        KcpConn::new(socket, *addr, None).await
    }

    /// 接受 WebSocket 连接
    ///
    /// # 参数
    ///
    /// * `stream` - 底层 TCP 流
    pub async fn accept_websocket(
        &self,
        stream: TokioTcpStream,
    ) -> Result<WebSocketConn<TokioTcpStream>, std::io::Error> {
        let remote_addr = stream.peer_addr()?;
        let stream = accept_async(stream)
            .await
            .map_err(|e| std::io::Error::other(e))?;
        Ok(WebSocketConn::new(stream, remote_addr))
    }

    /// 将连接放回连接池
    ///
    /// # 参数
    ///
    /// * `addr` - 连接目标地址
    /// * `conn` - 要放回的连接
    pub async fn put_back(&self, addr: SocketAddr, conn: PooledConn) {
        if let Some(pool) = self.pool_manager.get_pool(addr).await {
            pool.put(conn).await;
        }
    }

    /// 获取 TLS 配置
    pub fn get_tls_config(&self) -> Option<&TlsConfig> {
        self.tls_config.as_ref()
    }

    /// 获取连接池管理器
    pub fn get_pool_manager(&self) -> &PoolManager {
        &self.pool_manager
    }
}

// 导出连接池模块
pub mod pool;

// 重新导出连接池类型

/// KCP 协议的输出适配器，将 KCP 输出通过 channel 传递给异步 UDP 写任务
struct KcpChannelOutput {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl std::io::Write for KcpChannelOutput {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let data = buf.to_vec();
        let _ = self.tx.try_send(data);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// KCP 连接，实现了 AsyncRead + AsyncWrite + FrpConn
///
/// 内部通过后台任务维护 KCP 会话，将 UDP 数据包与 KCP 协议进行转换。
pub struct KcpConn {
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    remote_addr: SocketAddr,
    read_buf: Vec<u8>,
    _handle: tokio::task::JoinHandle<()>,
}

impl KcpConn {
    /// 创建新的 KCP 连接（客户端）
    ///
    /// # 参数
    ///
    /// * `socket` - UDP socket
    /// * `remote_addr` - 远程地址
    /// * `conv` - KCP 会话 ID（可选，默认为随机值）
    pub async fn new(
        socket: std::sync::Arc<tokio::net::UdpSocket>,
        remote_addr: SocketAddr,
        conv: Option<u32>,
    ) -> Result<Self, NetError> {
        let conv = conv.unwrap_or_else(rand::random::<u32>);
        Self::create_impl(socket, remote_addr, conv, None).await
    }

    /// 接受 KCP 连接（服务端）
    ///
    /// # 参数
    ///
    /// * `socket` - UDP socket
    /// * `first_packet` - 收到的第一个数据包（用于提取 conv）
    /// * `remote_addr` - 远程地址
    pub async fn accept(
        socket: std::sync::Arc<tokio::net::UdpSocket>,
        first_packet: &[u8],
        remote_addr: SocketAddr,
    ) -> Result<Self, NetError> {
        let conv = if first_packet.len() >= 4 {
            u32::from_le_bytes([
                first_packet[0],
                first_packet[1],
                first_packet[2],
                first_packet[3],
            ])
        } else {
            rand::random::<u32>()
        };
        Self::create_impl(socket, remote_addr, conv, Some(first_packet.to_vec())).await
    }

    async fn create_impl(
        socket: std::sync::Arc<tokio::net::UdpSocket>,
        remote_addr: SocketAddr,
        conv: u32,
        initial_input: Option<Vec<u8>>,
    ) -> Result<Self, NetError> {
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
        let (user_tx, mut user_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
        let (user_rx_tx, user_rx_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

        let socket_clone = socket.clone();

        let handle = tokio::spawn(async move {
            let kcp_output = KcpChannelOutput { tx: out_tx };
            let mut kcp = kcp::Kcp::new(conv, kcp_output);

            kcp.set_nodelay(true, 10, 2, true);
            kcp.set_wndsize(128, 128);
            let _ = kcp.set_mtu(1400);

            if let Some(data) = initial_input {
                let _ = kcp.input(&data);
            }

            let mut buf = vec![0u8; 65535];
            let mut recv_buf = vec![0u8; 65535];
            let mut tick_interval = tokio::time::interval(std::time::Duration::from_millis(10));

            loop {
                tokio::select! {
                    _ = tick_interval.tick() => {
                        // 使用毫秒时间戳
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u32;
                        let _ = kcp.update(now_ms);
                        // 更新后 flush 以发送 ACK 和重传数据
                        let _ = kcp.flush();
                    }

                    recv_result = socket_clone.recv_from(&mut buf) => {
                        match recv_result {
                            Ok((n, src)) if src == remote_addr => {
                                let _ = kcp.input(&buf[..n]);
                                while let Ok(n) = kcp.recv(&mut recv_buf) {
                                    if user_rx_tx.send(recv_buf[..n].to_vec()).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            Ok((_n, _src)) => {}
                            Err(_e) => {
                                break;
                            }
                        }
                    }

                    Some(out_data) = out_rx.recv() => {
                        let _ = socket_clone.send_to(&out_data, &remote_addr).await;
                    }

                    Some(user_data) = user_rx.recv() => {
                        let _ = kcp.send(&user_data);
                        let _ = kcp.flush();
                        while let Ok(n) = kcp.recv(&mut recv_buf) {
                            if user_rx_tx.send(recv_buf[..n].to_vec()).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            rx: user_rx_rx,
            tx: user_tx,
            remote_addr,
            read_buf: Vec::new(),
            _handle: handle,
        })
    }
}

impl AsyncRead for KcpConn {
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

        match self.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(data)) => {
                let len = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..len]);
                if len < data.len() {
                    self.read_buf.extend_from_slice(&data[len..]);
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "KCP connection closed",
            ))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl AsyncWrite for KcpConn {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let data = buf.to_vec();
        let len = data.len();
        match self.tx.try_send(data) {
            Ok(_) => std::task::Poll::Ready(Ok(len)),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // Channel is full, would block
                std::task::Poll::Pending
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => std::task::Poll::Ready(Err(
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "KCP send channel closed"),
            )),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl FrpConn for KcpConn {
    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote_addr)
    }
}

/// KCP 监听器，用于服务端接受 KCP 连接
pub struct KcpListener {
    socket: std::sync::Arc<tokio::net::UdpSocket>,
}

impl KcpListener {
    pub async fn bind(addr: SocketAddr) -> Result<Self, std::io::Error> {
        let socket = tokio::net::UdpSocket::bind(addr).await?;
        Ok(Self {
            socket: std::sync::Arc::new(socket),
        })
    }

    pub async fn accept(&self) -> Result<(KcpConn, SocketAddr), NetError> {
        let mut buf = vec![0u8; 65535];
        let (n, src_addr) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(NetError::Io)?;

        let first_packet = buf[..n].to_vec();
        let conn = KcpConn::accept(self.socket.clone(), &first_packet, src_addr).await?;

        Ok((conn, src_addr))
    }
}
pub use pool::{ConnPool, PoolConfig, PoolManager, PoolStats, PooledConn};
