//! FRP 客户端模块
//!
//! 该模块实现了 FRP 客户端（frpc）的核心功能。
//!
//! ## 客户端架构
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         Client                                  │
//! │  (主客户端结构，管理所有子组件)                                   │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!         ┌────────────────────┼────────────────────┐
//!         ▼                    ▼                    ▼
//! ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
//! │ ClientControl │   │ClientProxyMgr  │   │ClientVisitorMgr│
//! │ (控制连接)     │   │ (代理管理)     │   │ (访问者管理)   │
//! └───────────────┘   └───────────────┘   └───────────────┘
//!         │                    │                    │
//!         ▼                    ▼                    ▼
//! ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
//! │ WorkConnMgr   │   │  Connector    │   │  Connector    │
//! │ (工作连接管理) │   │ (网络连接)     │   │               │
//! └───────────────┘   └───────────────┘   └───────────────┘
//! ```
//!
//! ## 核心流程
//!
//! ### 1. 启动流程
//! ```text
//! Client::start()
//!   ├── 启动 Web 服务器（可选）
//!   ├── login() - 登录到服务器
//!   │     ├── 建立 TCP/TLS 连接
//!   │     ├── 发送 LoginMsg
//!   │     └── 接收 LoginRespMsg
//!   ├── 注册所有代理 (register_proxy)
//!   │     └── 发送 RegisterProxyMsg
//!   ├── 启动所有代理 (add_proxy)
//!   │     └── 创建工作连接处理器
//!   └── 运行控制循环 (run)
//!         ├── 处理服务器消息
//!         └── 监听信号退出
//! ```
//!
//! ### 2. 工作连接流程
//! ```text
//! 服务器                          客户端                          本地服务
//!   │                               │                              │
//!   │--- ReqWorkConnMsg ----------->│                              │
//!   │                               │                              │
//!   │                        establish_work_connection()            │
//!   │                               │                              │
//!   │                        连接工作端口 (server_port + 1000)       │
//!   │                               │                              │
//!   │<---- NewWorkConnMsg ----------│                              │
//!   │--- StartWorkConnMsg --------->│                              │
//!   │                               │ TcpStream::connect(local) -->│
//!   │                               │ 可选: PROXY header --------->│
//!   │<------ bridge_streams ------->│<---- bridge_streams -------->│
//! ```
//!
//! ## 安全性
//!
//! - TLS 加密连接（默认启用）
//! - HMAC 签名验证
//! - Token 认证
//! - 连接重试机制
//! - PROXY Protocol 支持（可选，透传真实访问者 IP）
//!
//! ## 配置示例
//!
//! ```toml
//! server_addr = "127.0.0.1"
//! server_port = 9300
//!
//! [[proxies]]
//! name = "ssh"
//! type = "tcp"
//! local_ip = "127.0.0.1"
//! local_port = 22
//! remote_port = 6000
//! ```

pub mod admin_client;

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::Engine as _;
use rust_frp_auth::AuthManager;
use rust_frp_config::ClientConfig;
use rust_frp_core::{ControlConn, Message, NewWorkConnMsg, ProxyManager, VisitorManager};
use rust_frp_net::{ConnManager, KcpStream, MuxSession, Session, TlsConfig, TCP_MUX_MAGIC};
use rust_frp_util::{
    get_timestamp, rand_id,
    retry::{retry, ConnectionError, RetryConfig},
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex, RwLock};

mod types;
pub use types::*;

mod transport;
pub use transport::*;

mod control;
pub use control::*;

mod work_conn;
use work_conn::*;

mod visitor;
use visitor::*;

mod sudp;
use sudp::*;

mod web;
pub use web::*;

mod client_impl;
pub use client_impl::*;

#[cfg(test)]
mod tests;
