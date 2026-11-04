//! 配置加载、includes 合并、环境变量替换与校验。

use super::*;

/// 配置加载器 - 负责配置的加载、解析和验证
///
/// # 功能
///
/// 1. 支持 TOML/YAML/JSON 多种格式
/// 2. 支持配置包含（glob 模式）
/// 3. 支持环境变量替换
/// 4. 配置验证
pub struct ConfigLoader;

impl ConfigLoader {
    /// 从文件加载服务器配置
    ///
    /// # 处理流程
    ///
    /// ```text
    /// 文件读取 -> 格式检测 -> 解析 -> includes合并 -> 环境变量替换 -> 验证
    /// ```
    ///
    /// # 参数
    ///
    /// - `path`: 配置文件路径
    ///
    /// # 返回值
    ///
    /// - 成功: `Ok(ServerConfig)`
    /// - 失败: `Box<dyn Error>`
    ///
    /// # 示例
    ///
    /// ```rust,no_run
    /// # use rust_frp_config::ConfigLoader;
    /// let config = ConfigLoader::load_server_config("frps.toml")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn load_server_config<P: AsRef<Path>>(
        path: P,
    ) -> Result<ServerConfig, Box<dyn std::error::Error>> {
        Self::load_server_config_strict(path, false)
    }

    /// 从文件加载服务端配置（严格模式可选，对齐原版 `--strict_config`）
    ///
    /// `strict = true` 时未知字段直接报错；`false` 时仅打印 WARN（缺省）。
    pub fn load_server_config_strict<P: AsRef<Path>>(
        path: P,
        strict: bool,
    ) -> Result<ServerConfig, Box<dyn std::error::Error>> {
        let mut config: ServerConfig =
            Self::load_config_from_file(path, ConfigKind::Server, strict)?;
        Self::process_includes(&mut config, strict)?;
        Self::replace_environment_variables(&mut config)?;
        Self::normalize_server_config(&mut config);
        Self::validate_server_config(&config)?;
        Ok(config)
    }

    /// 从文件加载客户端配置
    ///
    /// # 处理流程
    ///
    /// 与 `load_server_config` 类似，但针对客户端配置结构
    pub fn load_client_config<P: AsRef<Path>>(
        path: P,
    ) -> Result<ClientConfig, Box<dyn std::error::Error>> {
        Self::load_client_config_strict(path, false)
    }

    /// 从文件加载客户端配置（严格模式可选，对齐原版 `--strict_config`）
    ///
    /// `strict = true` 时未知字段直接报错；`false` 时仅打印 WARN（缺省）。
    pub fn load_client_config_strict<P: AsRef<Path>>(
        path: P,
        strict: bool,
    ) -> Result<ClientConfig, Box<dyn std::error::Error>> {
        let mut config = Self::load_config_from_file(path, ConfigKind::Client, strict)?;
        Self::process_includes_client(&mut config, strict)?;
        Self::replace_environment_variables_client(&mut config)?;
        Self::normalize_client_config(&mut config);
        Self::validate_client_config(&config)?;
        Ok(config)
    }

    /// 校验配置内容（不读文件、不落盘）
    ///
    /// 供客户端管理 API（`PUT /config`）使用：完整走「解析 → 归并 → 校验」
    /// 链路，任何一步失败都返回 Err。注意不处理 `includes`（相对路径解析
    /// 依赖配置文件所在目录，留待随后的 reload 从磁盘加载时处理）。
    pub fn validate_client_config_content(
        content: &str,
    ) -> Result<ClientConfig, Box<dyn std::error::Error>> {
        Self::validate_client_config_content_strict(content, false)
    }

    /// 校验配置内容（严格模式可选，对齐原版 `--strict_config`）
    ///
    /// `strict = true` 时未知字段直接报错；`false` 时仅打印 WARN（缺省）。
    pub fn validate_client_config_content_strict(
        content: &str,
        strict: bool,
    ) -> Result<ClientConfig, Box<dyn std::error::Error>> {
        let mut config = Self::parse_config::<ClientConfig>(content, ConfigKind::Client, strict)?;
        Self::normalize_client_config(&mut config);
        Self::validate_client_config(&config)?;
        Ok(config)
    }

    /// 校验服务端配置内容（不读文件、不落盘）
    ///
    /// 与 [`Self::validate_client_config_content`] 对称；fuzz / 基准测试与嵌入
    /// 场景可直接喂字符串。
    pub fn validate_server_config_content(
        content: &str,
    ) -> Result<ServerConfig, Box<dyn std::error::Error>> {
        Self::validate_server_config_content_strict(content, false)
    }

    /// 校验服务端配置内容（严格模式可选，对齐原版 `--strict_config`）
    ///
    /// `strict = true` 时未知字段直接报错；`false` 时仅打印 WARN（缺省）。
    pub fn validate_server_config_content_strict(
        content: &str,
        strict: bool,
    ) -> Result<ServerConfig, Box<dyn std::error::Error>> {
        let mut config = Self::parse_config::<ServerConfig>(content, ConfigKind::Server, strict)?;
        Self::normalize_server_config(&mut config);
        Self::validate_server_config(&config)?;
        Ok(config)
    }

    /// 从文件加载配置（通用方法）
    ///
    /// # 格式检测
    ///
    /// 按 TOML -> YAML -> JSON 顺序尝试解析
    ///
    /// # 性能优化
    ///
    /// 首次成功的格式会被记录，避免重复尝试
    fn load_config_from_file<P: AsRef<Path>, T: serde::de::DeserializeOwned + Default>(
        path: P,
        kind: ConfigKind,
        strict: bool,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let mut file = File::open(path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        // 注意：绝不能把配置原文写进日志——配置文件里通常包含 auth token、
        // web_server 密码、OIDC client_secret 等敏感信息。
        log::debug!("Loaded config content ({} bytes)", content.len());
        Self::parse_config(&content, kind, strict)
    }

    /// 解析配置内容
    ///
    /// # 格式优先级
    ///
    /// 1. TOML（首选，推荐）
    /// 2. YAML
    /// 3. JSON
    ///
    /// # 错误处理
    ///
    /// 所有格式都失败时返回错误
    pub(crate) fn parse_config<T: serde::de::DeserializeOwned + Default>(
        content: &str,
        kind: ConfigKind,
        strict: bool,
    ) -> Result<T, Box<dyn std::error::Error>> {
        // 按 TOML -> YAML -> JSON 顺序盲试；全部失败时把三种格式各自的
        // 错误信息汇总后抛出，避免排障时只能看到一句无信息量的
        // "Failed to parse config file"。
        let mut errors: Vec<String> = Vec::new();

        log::info!("Trying to parse config as TOML");
        match toml::from_str::<T>(content) {
            Ok(config) => {
                log::info!("Successfully parsed config as TOML");
                Self::check_raw_fields(content, kind, strict)?;
                return Ok(config);
            }
            Err(e) => {
                log::debug!("Failed to parse as TOML: {}", e);
                errors.push(format!("TOML: {}", e));
            }
        }

        log::info!("Trying to parse config as YAML");
        match serde_yaml::from_str::<T>(content) {
            Ok(config) => {
                log::info!("Successfully parsed config as YAML");
                Self::check_raw_fields(content, kind, strict)?;
                return Ok(config);
            }
            Err(e) => {
                log::debug!("Failed to parse as YAML: {}", e);
                errors.push(format!("YAML: {}", e));
            }
        }

        log::info!("Trying to parse config as JSON");
        match serde_json::from_str::<T>(content) {
            Ok(config) => {
                log::info!("Successfully parsed config as JSON");
                Self::check_raw_fields(content, kind, strict)?;
                return Ok(config);
            }
            Err(e) => {
                log::debug!("Failed to parse as JSON: {}", e);
                errors.push(format!("JSON: {}", e));
            }
        }

        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Failed to parse config file; attempted TOML/YAML/JSON, all failed:\n  {}",
                errors.join("\n  ")
            ),
        )))
    }

    /// 把原始配置文本转成 JSON Value 后处理未知字段。
    ///
    /// - 非严格模式（缺省）：打印 WARN（对齐 rust 的迁移友好策略）；
    /// - 严格模式（原版 `--strict_config`，默认 true）：直接报错。
    ///
    /// 解析失败时静默跳过（主解析已报错，告警无意义）。
    /// 把原始配置文本转成 JSON Value 后处理未知字段。
    ///
    /// - 非严格模式（缺省）：打印 WARN（对齐 rust 的迁移友好策略）；
    /// - 严格模式（原版 `--strict_config`，默认 true）：直接报错。
    ///
    /// 按与主解析相同的 TOML→YAML→JSON 顺序把原文转成 JSON Value，
    /// 再做字段名核对；三种格式都转不动时静默跳过（主解析已报错）。
    fn check_raw_fields(
        content: &str,
        kind: ConfigKind,
        strict: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json: serde_json::Value = if let Ok(v) = toml::from_str::<toml::Value>(content) {
            serde_json::to_value(v)?
        } else if let Ok(v) = serde_yaml::from_str::<serde_yaml::Value>(content) {
            serde_json::to_value(v)?
        } else if let Ok(v) = serde_json::from_str::<serde_json::Value>(content) {
            v
        } else {
            return Ok(());
        };
        if strict {
            if let Some(msg) = compat::strict_unknown_error(kind, &json) {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, msg).into());
            }
            return Ok(());
        }
        compat::warn_unknown_fields(kind, &json);
        Ok(())
    }

    /// 归并代理级 transport 子表中的应用层加密开关。
    ///
    /// 原版 frp 把 `useEncryption` 放在 `[[proxies]].transport` 子表中，
    /// 本实现的主开关在代理顶层 `use_encryption`；两者任一为 true 即生效。
    fn normalize_server_config(config: &mut ServerConfig) {
        for proxy in &mut config.proxies {
            if let Some(t) = &proxy.transport {
                if t.use_encryption {
                    proxy.use_encryption = true;
                }
            }
        }
    }

    /// 客户端版归并：除代理外还处理 `[[visitors]].transport.useEncryption`
    fn normalize_client_config(config: &mut ClientConfig) {
        for proxy in &mut config.proxies {
            if let Some(t) = &proxy.transport {
                if t.use_encryption {
                    proxy.use_encryption = true;
                }
                if t.use_compression {
                    proxy.use_compression = true;
                }
            }
        }
        for visitor in &mut config.visitors {
            if let Some(t) = &visitor.transport {
                if t.use_encryption {
                    visitor.use_encryption = true;
                }
                if t.use_compression {
                    visitor.use_compression = true;
                }
            }
        }
    }

    /// 处理服务器配置文件包含
    ///
    /// # includes 机制
    ///
    /// 通过 glob 模式匹配多个配置文件并合并：
    ///
    /// ```toml
    /// includes = ["/etc/frp.d/*.toml", "/home/*/frp.conf"]
    /// ```
    ///
    /// # 合并规则
    ///
    /// - 标量值：后者覆盖前者
    /// - 数组（如 proxies）：扩展合并
    fn process_includes(
        config: &mut ServerConfig,
        strict: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let includes = config.includes.clone();
        if let Some(includes) = includes {
            for pattern in includes {
                let files = glob(&pattern)?;
                for file in files {
                    match file {
                        Ok(path) => {
                            let include_config =
                                Self::load_config_from_file(path, ConfigKind::Server, strict)?;
                            Self::merge_server_config(config, &include_config);
                        }
                        Err(e) => {
                            log::warn!("glob error: {:?}", e);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// 处理客户端配置文件包含
    ///
    /// 与 `process_includes` 类似，但针对客户端配置
    fn process_includes_client(
        config: &mut ClientConfig,
        strict: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let includes = config.includes.clone();
        if let Some(includes) = includes {
            for pattern in includes {
                let files = glob(&pattern)?;
                for file in files {
                    match file {
                        Ok(path) => {
                            let include_config =
                                Self::load_config_from_file(path, ConfigKind::Client, strict)?;
                            Self::merge_client_config(config, &include_config);
                        }
                        Err(e) => {
                            log::warn!("glob error: {:?}", e);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// 合并服务器配置
    ///
    /// # 合并策略
    ///
    /// - 值为零值或空时不覆盖
    /// - 数组字段（如 proxies）使用 extend 合并
    pub(crate) fn merge_server_config(target: &mut ServerConfig, source: &ServerConfig) {
        if !source.bind_addr.is_empty() {
            target.bind_addr = source.bind_addr.clone();
        }
        if source.bind_port != 0 {
            target.bind_port = source.bind_port;
        }
        if source.kcp_bind_port.is_some() {
            target.kcp_bind_port = source.kcp_bind_port;
        }
        if source.quic_bind_port.is_some() {
            target.quic_bind_port = source.quic_bind_port;
        }
        if source.vhost_http_port.is_some() {
            target.vhost_http_port = source.vhost_http_port;
        }
        if source.vhost_https_port.is_some() {
            target.vhost_https_port = source.vhost_https_port;
        }
        if source.tcpmux_http_connect_port.is_some() {
            target.tcpmux_http_connect_port = source.tcpmux_http_connect_port;
        }
        target.proxies.extend(source.proxies.clone());
    }

    /// 合并客户端配置
    ///
    /// # 合并策略
    ///
    /// - 值为 None 或零值时不覆盖
    /// - proxies 和 visitors 使用 extend 合并
    pub(crate) fn merge_client_config(target: &mut ClientConfig, source: &ClientConfig) {
        if !source.server_addr.is_empty() {
            target.server_addr = source.server_addr.clone();
        }
        if source.server_port != 0 {
            target.server_port = source.server_port;
        }
        if source.user.is_some() {
            target.user = source.user.clone();
        }
        if source.client_id.is_some() {
            target.client_id = source.client_id.clone();
        }
        target.proxies.extend(source.proxies.clone());
        target.visitors.extend(source.visitors.clone());
    }

    /// 替换字符串中的环境变量
    ///
    /// # 语法
    ///
    /// `${VAR_NAME}`
    ///
    /// # 示例
    ///
    /// ```toml
    /// server_addr = "${FRP_SERVER_ADDR}"
    /// ```
    ///
    /// 如果环境变量不存在，替换为空字符串
    pub(crate) fn replace_env_vars(s: &str) -> String {
        let mut result = s.to_string();
        while let Some(start) = result.find("${") {
            if let Some(end) = result[start + 2..].find('}') {
                let var_name = &result[start + 2..start + 2 + end];
                let var_value = std::env::var(var_name).unwrap_or_default();
                result.replace_range(start..start + 3 + end, &var_value);
            } else {
                break;
            }
        }
        result
    }

    /// 替换服务器配置中的环境变量
    fn replace_environment_variables(
        config: &mut ServerConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        config.bind_addr = Self::replace_env_vars(&config.bind_addr);
        if let Some(ref mut includes) = config.includes {
            for item in includes.iter_mut() {
                *item = Self::replace_env_vars(item);
            }
        }
        for proxy in config.proxies.iter_mut() {
            proxy.local_ip = Self::replace_env_vars(&proxy.local_ip);
        }
        Ok(())
    }

    /// 替换客户端配置中的环境变量
    fn replace_environment_variables_client(
        config: &mut ClientConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        config.server_addr = Self::replace_env_vars(&config.server_addr);
        if let Some(ref mut includes) = config.includes {
            for item in includes.iter_mut() {
                *item = Self::replace_env_vars(item);
            }
        }
        for proxy in config.proxies.iter_mut() {
            proxy.local_ip = Self::replace_env_vars(&proxy.local_ip);
        }
        Ok(())
    }

    /// 校验登录节流配置：开了节流就必须给出锁定时长，避免"锁 0 秒"这种歧义配置。
    ///
    /// `login_max_failures = 0` 表示**显式关闭**节流；一旦大于 0，
    /// `login_lockout_secs` 必须为正 —— 否则会被理解为"立刻解锁"，等于没节流。
    fn validate_auth_throttle(auth: &AuthConfig) -> Result<(), Box<dyn std::error::Error>> {
        if auth.login_max_failures > 0 && auth.login_lockout_secs == 0 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "auth.login_max_failures > 0 requires auth.login_lockout_secs > 0 \
                 (a zero lockout window would make the throttle a no-op)",
            )));
        }
        Ok(())
    }

    /// 校验服务端 mTLS 配置：要"强制"客户端证书，必须先有可校验它的 CA。
    ///
    /// 这条校验的意义：`require_client_cert = true` 而无 `client_ca_file` 是**无意义**的
    /// 组合（无法校验就不存在可强制的对象），若静默放行会给人"已启用 mTLS"的错觉。
    fn validate_tls_server_mtls(tls: &Option<TlsConfig>) -> Result<(), Box<dyn std::error::Error>> {
        let Some(tls) = tls else { return Ok(()) };
        if tls.require_client_cert && tls.client_ca_file.as_deref().unwrap_or("").is_empty() {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "transport.tls.require_client_cert = true requires transport.tls.client_ca_file \
                 (client certificates cannot be enforced without a CA to verify them)",
            )));
        }
        Ok(())
    }

    /// 校验客户端 mTLS 配置：`cert_file`/`key_file` 必须成对，且不得与 `skip_verify` 同现。
    ///
    /// 两条规则都指向同一件事 —— 别让"以为开了 mTLS"落空：
    /// - 只配一半（有证书无私钥）无法出示证书，握手必失败，应尽早报错；
    /// - `skip_verify = true` 表示"不校验服务端身份"，与 mTLS 同时使用会留下**假服务端
    ///   钓鱼**的口子（客户端会照样向冒充者出示证书），因此直接拒绝（设计稿 D7）。
    fn validate_tls_client_mtls(tls: &Option<TlsConfig>) -> Result<(), Box<dyn std::error::Error>> {
        let Some(tls) = tls else { return Ok(()) };
        let (cert, key) = (tls.cert_file.as_deref(), tls.key_file.as_deref());
        if cert.is_some() != key.is_some() {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "transport.tls.cert_file and transport.tls.key_file must be configured together \
                 (they carry the client certificate presented for mTLS)",
            )));
        }
        if cert.is_some() && tls.skip_verify {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "transport.tls.skip_verify = true cannot be combined with a client certificate \
                 (cert_file/key_file): skipping server verification would let an impostor server \
                 collect the client certificate. Remove skip_verify and set trusted_ca_file to \
                 pin the server CA instead.",
            )));
        }
        Ok(())
    }

    /// 验证服务器配置
    ///
    /// # 必填字段
    ///
    /// - `bind_port`: 必须大于 0
    pub(crate) fn validate_server_config(
        config: &ServerConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if config.bind_port == 0 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "bind_port is required",
            )));
        }

        Self::validate_tls_server_mtls(&config.transport.tls)?;
        Self::validate_auth_throttle(&config.auth)?;

        // Web 管理端凭据必须成对配置：只填一半会导致鉴权被静默关闭，
        // dashboard 直接对全网暴露，因此这里直接拒绝启动。
        let web = &config.web_server;
        if web.port != 0 {
            match (&web.user, &web.password) {
                (Some(user), Some(password)) => {
                    if user.is_empty() || password.is_empty() {
                        return Err(Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "web_server.user and web_server.password must be non-empty \
                             (an empty credential would disable dashboard authentication)",
                        )));
                    }
                    if user == "admin" && password == "admin" {
                        log::warn!(
                            "web_server is using the default admin/admin credentials; \
                             change them before exposing the dashboard"
                        );
                    }
                }
                (None, None) => {
                    // 安全评审 P1：此前这里只打一条 warn 就继续启动。由于鉴权中间件
                    // 在 `requires_login() == false` 时**根本不挂载**（web.rs），
                    // 结果是 fail-open——dashboard 的全部页面连同**有副作用的
                    // `POST /api/reload`** 对任何能访问该端口的人开放。
                    // 现在直接拒绝启动：要么配齐凭据，要么显式 `port = 0` 关掉 dashboard。
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "web_server.port is set but web_server.user/password are missing: \
                         an unauthenticated dashboard would expose every page and the \
                         side-effecting /api/reload endpoint to anyone who can reach the \
                         port. Set both user and password, or set web_server.port = 0 to \
                         disable the dashboard.",
                    )));
                }
                _ => {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "web_server.user and web_server.password must be configured together",
                    )));
                }
            }
        }

        // 自定义域名白名单：条目自身必须是合法域名。否则一条笔误会让白名单在
        // 运行时静默失效（例如误写成 "*"），等于没收口，所以启动时就拒绝。
        for domain in &config.custom_domains_allowlist {
            if let Err(e) = validate_custom_domain(domain) {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("custom_domains_allowlist entry {domain:?} is invalid: {e}"),
                )));
            }
        }

        // KCP 与 QUIC 都是 UDP 监听：同端口会第二个 bind 失败，提前拒绝更清晰
        if let (Some(kcp), Some(quic)) = (config.kcp_bind_port, config.quic_bind_port) {
            if kcp == quic && quic > 0 {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "kcp_bind_port and quic_bind_port cannot share the same UDP port ({kcp})"
                    ),
                )));
            }
        }

        // 服务端 HTTP 插件：name/addr/ops 必须有效，op 必须是已知回调类型。
        // 非法配置直接拒绝启动，避免「配了插件却静默不回调」。
        for (i, plugin) in config.http_plugins.iter().enumerate() {
            if plugin.name.trim().is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("http_plugins[{i}].name must be non-empty"),
                )));
            }
            if plugin.addr.trim().is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("http_plugins[{i}].addr must be non-empty"),
                )));
            }
            if plugin.ops.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "http_plugins[{i}] ({}) subscribes to no operation; \
                         ops must list at least one of {VALID_PLUGIN_OPS:?}",
                        plugin.name
                    ),
                )));
            }
            for op in &plugin.ops {
                if !VALID_PLUGIN_OPS.contains(&op.as_str()) {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "http_plugins[{i}] ({}) has unknown op {:?}; valid ops are {VALID_PLUGIN_OPS:?}",
                            plugin.name, op
                        ),
                    )));
                }
            }
        }

        // OIDC：服务端必须配置 issuer —— 它是发现文档与 JWKS 的入口，
        // 缺失会导致「配了 oidc 却无法验签」。鉴权方法本身也要合法。
        match config.auth.method.as_str() {
            "token" => {}
            "oidc" => {
                let Some(oidc) = config.auth.oidc.as_ref() else {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "auth.oidc is required when auth.method = \"oidc\"",
                    )));
                };
                if oidc.issuer.trim().is_empty() {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "auth.oidc.issuer is required for server-side OIDC token verification",
                    )));
                }
            }
            other => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("unsupported auth.method: {other} (expected \"token\" or \"oidc\")"),
                )));
            }
        }

        Ok(())
    }

    /// 校验一个绝对的 http/https URL（含非空 host）
    fn validate_absolute_http_url(
        value: &str,
        field: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for scheme in ["http://", "https://"] {
            if let Some(rest) = value.strip_prefix(scheme) {
                let host = rest.split(['/', '?', '#']).next().unwrap_or("");
                if !host.is_empty() {
                    return Ok(());
                }
            }
        }
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{field} = \"{value}\" must be an absolute http or https URL"),
        )))
    }

    /// 校验带宽限制字符串
    ///
    /// 支持 `"1GB"` / `"10MB"` / `"500KB"` / `"1024B"` / `"1024"`（纯字节数）。
    /// 非法值（空串、非数字、`0`、负数）一律报错——避免出现「配置里写了限速，
    /// 运行期却被静默忽略」的情况。
    fn validate_bandwidth_limit(
        value: &str,
        field: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let upper = value.trim().to_uppercase();
        let num_part = if let Some(n) = upper.strip_suffix("GB") {
            n.trim()
        } else if let Some(n) = upper.strip_suffix("MB") {
            n.trim()
        } else if let Some(n) = upper.strip_suffix("KB") {
            n.trim()
        } else if let Some(n) = upper.strip_suffix('B') {
            n.trim()
        } else {
            upper.as_str()
        };

        let valid = num_part
            .parse::<f64>()
            .map(|v| v.is_finite() && v > 0.0)
            .unwrap_or(false);

        if valid {
            Ok(())
        } else {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "{} = \"{}\" is invalid; expected a positive value such as \
                     \"1GB\", \"10MB\", \"500KB\" or a plain number of bytes",
                    field, value
                ),
            )))
        }
    }

    /// 校验 `auth.tokenSource`：与静态 token 互斥、类型合法、必填字段到位。
    /// 校验 `auth.additional_scopes`（对齐原版 `auth.additionalScopes`）
    ///
    /// - 值仅允许 `heartBeats` / `newWorkConns`；
    /// - `heartBeats` 的 Ping 签名密钥来自静态 token，必须 `method = "token"`
    ///   且 token 非空（fail-closed，OIDC 动态令牌不支持心跳签名）。
    fn validate_additional_scopes(auth: &AuthConfig) -> Result<(), Box<dyn std::error::Error>> {
        let Some(scopes) = auth.additional_scopes.as_ref() else {
            return Ok(());
        };
        for scope in scopes {
            if !["heartBeats", "newWorkConns"].contains(&scope.as_str()) {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "auth.additional_scopes value {:?} is not supported (expected \"heartBeats\" or \"newWorkConns\")",
                        scope
                    ),
                )));
            }
        }
        if scopes.iter().any(|s| s == "heartBeats")
            && (auth.method != "token"
                || auth
                    .token
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty())
        {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "auth.additional_scopes \"heartBeats\" requires auth.method = \"token\" with a non-empty token",
            )));
        }
        Ok(())
    }

    fn validate_token_source(auth: &AuthConfig) -> Result<(), Box<dyn std::error::Error>> {
        let Some(ts) = auth.token_source.as_ref() else {
            return Ok(());
        };
        if auth.token.as_deref().is_some_and(|t| !t.is_empty()) {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "auth.token and auth.tokenSource are mutually exclusive; set only one",
            )));
        }
        match ts.r#type.as_str() {
            "file" => {
                if ts.file_path.as_deref().is_none_or(|p| p.trim().is_empty()) {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "auth.tokenSource.filePath is required when type = \"file\"",
                    )));
                }
            }
            "exec" => {
                if ts.exec.as_ref().is_none_or(|v| v.is_empty()) {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "auth.tokenSource.exec must list the program to run when type = \"exec\"",
                    )));
                }
            }
            other => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "unsupported auth.tokenSource.type: {other} (expected \"file\" or \"exec\")"
                    ),
                )));
            }
        }
        Ok(())
    }

    /// 验证客户端配置
    ///
    /// # 必填字段
    ///
    /// - `server_addr`: 不能为空
    /// - `server_port`: 必须大于 0
    pub(crate) fn validate_client_config(
        config: &ClientConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if config.server_addr.is_empty() {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "server_addr is required",
            )));
        }
        if config.server_port == 0 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "server_port is required",
            )));
        }

        Self::validate_tls_client_mtls(&config.transport.tls)?;

        // 带宽限制：非法值直接报错，而不是运行期被静默丢弃
        if let Some(limit) = &config.transport.bandwidth_limit {
            Self::validate_bandwidth_limit(limit, "transport.bandwidth_limit")?;
        }

        // 传输协议：非法值直接报错，避免拼写错误静默回退到 TCP
        const VALID_PROTOCOLS: &[&str] = &["tcp", "kcp", "quic", "websocket", "wss"];
        if !VALID_PROTOCOLS.contains(&config.transport.protocol.as_str()) {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "transport.protocol {:?} is not supported (expected one of {:?})",
                    config.transport.protocol, VALID_PROTOCOLS
                ),
            )));
        }

        // 线协议版本：v1（默认，明文帧）/ v2（魔数 + 能力协商 + 方向性 AEAD）。
        // v2 的基础密钥由 token 派生（SHA-256(token)），因此要求 token 认证。
        const VALID_WIRE_PROTOCOLS: &[&str] = &["v1", "v2"];
        if !VALID_WIRE_PROTOCOLS.contains(&config.transport.wire_protocol.as_str()) {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "transport.wire_protocol {:?} is not supported (expected one of {:?})",
                    config.transport.wire_protocol, VALID_WIRE_PROTOCOLS
                ),
            )));
        }
        if config.transport.wire_protocol == "v2" && config.auth.method != "token" {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "transport.wire_protocol = \"v2\" requires auth.method = \"token\": \
                 the v2 control channel derives its AEAD keys from SHA-256(token)",
            )));
        }

        // QUIC / WSS 强制 TLS：QUIC 无明文模式；WSS 语义即为「TLS + WebSocket」。
        // 与 TLS 一致地 fail-closed 要求显式信任来源（pin CA 或显式 skip_verify）。
        if matches!(config.transport.protocol.as_str(), "quic" | "wss") {
            let tls = config.transport.tls.as_ref();
            let has_ca = tls
                .and_then(|t| t.trusted_ca_file.as_deref())
                .is_some_and(|f| !f.trim().is_empty());
            let insecure = tls.is_some_and(|t| t.skip_verify);
            if !has_ca && !insecure {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "transport.protocol = \"{}\" always uses TLS and has no plaintext \
                         mode: set transport.tls.trusted_ca_file to pin the server CA, or \
                         transport.tls.skip_verify = true to accept encryption without \
                         authentication",
                        config.transport.protocol
                    ),
                )));
            }
        }

        for proxy in &config.proxies {
            if let Some(limit) = &proxy.bandwidth_limit {
                Self::validate_bandwidth_limit(
                    limit,
                    &format!("proxies[name={}].bandwidth_limit", proxy.name),
                )?;
            }

            // PROXY protocol 版本：仅允许 v1 / v2（对齐原版校验）
            if let Some(version) = proxy.proxy_protocol_version.as_deref() {
                if !["v1", "v2"].contains(&version) {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "proxies[name={}].proxy_protocol_version {:?} is not supported (expected \"v1\" or \"v2\")",
                            proxy.name, version
                        ),
                    )));
                }
            }

            // tcpmux：仅支持 httpconnect 复用器，且必须配置域名（服务器按域名路由）
            if proxy.r#type == "tcpmux" {
                if let Some(multiplexer) = proxy.multiplexer.as_deref() {
                    if !multiplexer.is_empty() && multiplexer != "httpconnect" {
                        return Err(Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "proxies[name={}].multiplexer [{}] is not supported (only \"httpconnect\")",
                                proxy.name, multiplexer
                            ),
                        )));
                    }
                }
                let has_domain = proxy
                    .custom_domains
                    .as_ref()
                    .is_some_and(|domains| domains.iter().any(|d| !d.is_empty()))
                    || proxy.subdomain.as_deref().is_some_and(|s| !s.is_empty());
                if !has_domain {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "proxies[name={}] is a tcpmux proxy and requires custom_domains or subdomain",
                            proxy.name
                        ),
                    )));
                }
            }
        }

        // additionalScopes：值必须合法；heartBeats 签名依赖静态 token（fail-closed）
        Self::validate_additional_scopes(&config.auth)?;

        // OIDC 客户端：client_credentials 需要 client_id 与绝对 http(s) 的令牌端点。
        match config.auth.method.as_str() {
            "token" => {
                Self::validate_token_source(&config.auth)?;
            }
            "oidc" => {
                let Some(oidc) = config.auth.oidc.as_ref() else {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "auth.oidc is required when auth.method = \"oidc\"",
                    )));
                };
                if oidc.client_id.trim().is_empty() {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "auth.oidc.client_id is required for OIDC client credentials",
                    )));
                }
                Self::validate_absolute_http_url(
                    oidc.token_endpoint_url.trim(),
                    "auth.oidc.token_endpoint_url",
                )?;
                if oidc.additional_endpoint_params.contains_key("scope") {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "auth.oidc.additional_endpoint_params.scope is not allowed; \
                         use auth.oidc.scope instead",
                    )));
                }
                if !oidc.audience.is_empty()
                    && oidc.additional_endpoint_params.contains_key("audience")
                {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "cannot specify both auth.oidc.audience and \
                         auth.oidc.additional_endpoint_params.audience",
                    )));
                }
            }
            other => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("unsupported auth.method: {other} (expected \"token\" or \"oidc\")"),
                )));
            }
        }

        Ok(())
    }
}
