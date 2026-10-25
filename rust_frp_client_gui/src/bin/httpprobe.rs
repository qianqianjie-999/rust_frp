//! 探针：复刻 GUI 轮询器的裸 HTTP 交换，定位「进程内 HTTP 无响应」问题
//! 用法: httpprobe [port]

use std::io::{Read, Write};
use std::time::Duration;

fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(18610);
    let addr = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    println!("连接 {addr} ...");
    let mut stream = match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(800)) {
        Ok(s) => s,
        Err(e) => {
            println!("连接失败: {e}");
            std::process::exit(1);
        }
    };
    println!("连接成功, local={}", stream.local_addr().unwrap());
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let req = b"GET /status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    println!("发送 {} 字节", req.len());
    stream.write_all(req).expect("write");
    let mut resp = String::new();
    match stream.read_to_string(&mut resp) {
        Ok(_) => println!(
            "读取 {} 字节: {:?}",
            resp.len(),
            &resp[..resp.len().min(200)]
        ),
        Err(e) => println!("读取失败: {e} (已读 {} 字节)", resp.len()),
    }
}
