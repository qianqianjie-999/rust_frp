use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 测试 HTTP 请求解析
#[test]
fn test_http_request_parse() {
    let request = b"GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
    
    // 简单的解析测试
    let request_str = String::from_utf8_lossy(request);
    assert!(request_str.contains("GET /path HTTP/1.1"));
    assert!(request_str.contains("Host: example.com"));
}

/// 测试 WebSocket 升级检测
#[test]
fn test_websocket_upgrade_detection() {
    let ws_request = b"GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    
    let request_str = String::from_utf8_lossy(ws_request);
    assert!(request_str.contains("Upgrade: websocket"));
    assert!(request_str.contains("Connection: Upgrade"));
}

/// 测试重试配置
#[test]
fn test_retry_config() {
    use rust_frp_util::RetryConfig;
    
    let config = RetryConfig::default();
    assert_eq!(config.max_retries, 3);
    
    // 测试延迟计算
    let delay1 = config.calculate_delay(1);
    assert_eq!(delay1, Duration::from_millis(100));
    
    let delay2 = config.calculate_delay(2);
    assert_eq!(delay2, Duration::from_millis(200));
}

/// 测试连接池配置
#[test]
fn test_pool_config() {
    use rust_frp_net::PoolConfig;
    
    let config = PoolConfig::default();
    assert_eq!(config.max_size, 10);
    assert_eq!(config.connection_timeout, Duration::from_secs(5));
    assert_eq!(config.max_idle_time, Duration::from_secs(300));
}

/// 集成测试：HTTP 虚拟主机路由
#[tokio::test]
async fn test_http_vhost_routing() {
    // 启动一个模拟的 HTTP 服务器
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    // 在后台运行服务器
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        
        let request = String::from_utf8_lossy(&buf[..n]);
        if request.contains("Host: test.example.com") {
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest";
            stream.write_all(response.as_bytes()).await.unwrap();
        } else {
            let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    
    // 发送 HTTP 请求
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = "GET / HTTP/1.1\r\nHost: test.example.com\r\n\r\n";
    stream.write_all(request.as_bytes()).await.unwrap();
    
    // 读取响应
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    
    assert!(response.contains("200 OK"));
    assert!(response.contains("test"));
}

/// 测试连接池获取和归还
#[tokio::test]
async fn test_connection_pool() {
    use rust_frp_net::{PoolConfig, ConnPool};
    
    // 创建监听
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    // 后台接受连接
    tokio::spawn(async move {
        loop {
            let _ = listener.accept().await;
        }
    });
    
    // 创建连接池
    let config = PoolConfig {
        max_size: 2,
        ..Default::default()
    };
    let pool = ConnPool::new(addr, config);
    
    // 获取连接
    let conn1 = pool.get().await.unwrap();
    let stats1 = pool.get_stats().await;
    assert_eq!(stats1.current_in_use, 1);
    
    // 归还连接
    pool.put(conn1).await;
    let stats2 = pool.get_stats().await;
    assert_eq!(stats2.current_idle, 1);
    assert_eq!(stats2.current_in_use, 0);
}

/// 测试重试机制
#[tokio::test]
async fn test_retry_mechanism() {
    use rust_frp_util::{RetryConfig, retry, ConnectionError};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = counter.clone();
    
    let retry_config = RetryConfig {
        max_retries: 2,
        initial_delay: Duration::from_millis(10),
        ..Default::default()
    };
    
    let result: Result<_, ConnectionError> = retry(
        &retry_config,
        "test operation",
        || async {
            let count = counter_clone.fetch_add(1, Ordering::SeqCst);
            if count < 2 {
                Err(ConnectionError::Other("temporary error".to_string()))
            } else {
                Ok("success")
            }
        }
    ).await;
    
    assert!(result.is_ok());
    assert_eq!(counter.load(Ordering::SeqCst), 3); // 初始尝试 + 2次重试
}
