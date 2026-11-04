//! TLS / QUIC / 连接预检等无状态辅助函数。

use super::*;

/// 由 `transport.quic` 构造 QUIC 传输参数（未配置时用与原版 frp 一致的默认值）
pub(super) fn quic_options(config: &ServerConfig) -> QuicOptions {
    let q = config.transport.quic.as_ref();
    QuicOptions::from_config(
        q.and_then(|q| q.max_idle_timeout),
        q.and_then(|q| q.max_incoming_streams),
        q.and_then(|q| q.keepalive_period),
    )
}

/// 由 `transport.tls` 构造服务端 TLS 配置（控制面与工作连接共用同一份逻辑）
///
/// - 配了 `cert_file`/`key_file` → 用自定义证书；否则用运行时自签证书；
/// - 配了 `client_ca_file` → 启用 **mTLS**（校验客户端证书链），`require_client_cert`
///   决定"未出示证书是否放行"（`false` = 灰度期放行）。
///
/// 放在这里统一两份重复构建逻辑（构造期与 TCP 监听循环各一处），避免只改其中一处
/// 导致 QUIC/TCP 行为不一致。
/// 取出 TLS 对端（客户端）证书的 SHA-256 指纹（薄封装，便于阅读与替换实现）
pub(super) fn peer_cert_fingerprint_of<S>(
    stream: &tokio_rustls::server::TlsStream<S>,
) -> Option<String> {
    rust_frp_net::peer_cert_fingerprint(stream)
}

/// 日志用短指纹（前 16 个 hex 字符）：够区分不同证书，又不至于刷屏
pub(super) fn short_fp(fp: &str) -> &str {
    &fp[..fp.len().min(16)]
}

pub(super) fn build_server_tls_config(
    tls: &rust_frp_config::TlsConfig,
) -> Result<TlsConfig, Box<dyn std::error::Error>> {
    let client_ca = tls.client_ca_file.as_deref();
    let require = tls.require_client_cert;

    if client_ca.is_some() && tls.cert_file.is_none() {
        log::warn!(
            "transport.tls.client_ca_file is configured without cert_file/key_file: mTLS will \
             verify client certificates, but the server keeps its runtime self-signed certificate \
             (clients cannot pin the server identity)"
        );
    }

    let net_tls = if let (Some(cert_file), Some(key_file)) = (&tls.cert_file, &tls.key_file) {
        TlsConfig::new_server(cert_file, key_file, client_ca, require)?
    } else {
        TlsConfig::new_server_with_runtime_cert(client_ca, require)?
    };
    Ok(net_tls)
}

/// P1 准入策略：服务端是否必须**拒绝**明文 WebSocket 控制连接。
///
/// 明文 ws 分支（`handle_connection` 首字节嗅探命中 `GET `）走的是
/// `accept_websocket_stream`（不套 TLS）+ `spawn_control(..., None)`，
/// **不校验客户端证书** —— 也就是说 `require_client_cert = true` 管不到它，
/// 持 token 者可用 `ws://<frps>:<bind_port>` 绕过 mTLS 层。
///
/// 因此在这两种"服务端要求更强传输保证"的配置下直接拒绝：
/// - `transport.tls.force`（本实现的 `tls_only`）：强制 TLS，明文一律拒绝；
/// - `transport.tls.require_client_cert = true`：强制客户端证书。
///
/// 抽成纯函数是为了能被单测覆盖（`handle_connection` 内部无法单测）。
pub(super) fn plaintext_ws_must_be_rejected(
    tls_only: bool,
    tls: Option<&rust_frp_config::TlsConfig>,
) -> bool {
    // `enable = false` 时全局就没有 TLS，拒绝明文 ws 只会造成"一半客户端连不上"，
    // 不产生任何安全收益（该场景应靠配置校验解决，见 REFERENCE §12.3 后续项）。
    let require_client_cert = tls
        .map(|t| t.enable && t.require_client_cert)
        .unwrap_or(false);
    tls_only || require_client_cert
}

pub(super) fn should_start_vhost_https(tls: Option<&rust_frp_config::TlsConfig>) -> bool {
    tls.is_some_and(|tls| tls.enable)
}
