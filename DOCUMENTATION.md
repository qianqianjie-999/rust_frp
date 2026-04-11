# Rust FRP Documentation

## Project Structure

The Rust FRP project is organized as a workspace with multiple crates:

```
rust_frp/
├── rust_frp_core/      # Core functionality and message definitions
├── rust_frp_server/    # Server implementation
├── rust_frp_client/    # Client implementation
├── rust_frp_config/    # Configuration management
├── rust_frp_net/       # Network communication
├── rust_frp_auth/      # Authentication management
├── rust_frp_plugin/    # Plugin system
├── rust_frp_util/      # Utility functions
├── frps.toml           # Server configuration file
├── frpc.toml           # Client configuration file
├── CONFIGURATION.md    # Configuration documentation
└── DOCUMENTATION.md    # This documentation
```

## Building the Project

### Prerequisites

- Rust 1.56+ (with Cargo)
- OpenSSL development libraries

### Build Commands

```bash
# Build the entire project
cargo build

# Build only the server
cargo build -p rust_frp_server

# Build only the client
cargo build -p rust_frp_client
```

## Running the Project

### Server

```bash
# Run the server with the default configuration
cargo run --bin frps -- -c frps.toml

# Run the server with a custom configuration
cargo run --bin frps -- -c /path/to/config.toml
```

### Client

```bash
# Run the client with the default configuration
cargo run --bin frpc -- -c frpc.toml

# Run the client with a custom configuration
cargo run --bin frpc -- -c /path/to/config.toml
```

## Configuration

### Server Configuration (frps.toml)

```toml
# Server basic configuration
bind_addr = "0.0.0.0"
bind_port = 7000

# Web server configuration
[web_server]
addr = "0.0.0.0"
port = 7500
user = "admin"
password = "admin"

# Authentication configuration
[auth]
method = "token"
token = "test_token"

# Transport configuration
[transport]
protocol = "tcp"
tls = { enable = true }  # Use built-in certificate
```

### Client Configuration (frpc.toml)

```toml
# Server connection configuration
server_addr = "127.0.0.1"
server_port = 7000
user = "client"

# Web server configuration
[web_server]
addr = "127.0.0.1"
port = 7400
user = "admin"
password = "admin"

# Authentication configuration
[auth]
method = "token"
token = "test_token"

# Transport configuration
[transport]
protocol = "tcp"
tls = { enable = true }  # Use built-in certificate

# Proxy configuration
proxies = [
  { name = "tcp_proxy", type = "tcp", local_ip = "127.0.0.1", local_port = 8080, remote_port = 8080 },
  { name = "http_proxy", type = "http", local_ip = "127.0.0.1", local_port = 80, custom_domains = ["example.com"] }
]
```

## Features

### Currently Implemented

- **Binary targets** for both server (frps) and client (frpc)
- **Basic TCP proxy** functionality with local and remote listeners
- **Basic HTTP proxy** functionality with local and remote listeners
- **TLS encryption** using built-in or custom certificates
- **Authentication** using token-based method
- **Web management interfaces** for both server and client
- **Configuration management** with support for TOML, YAML, and JSON formats

### Not Yet Implemented

- **Actual proxy forwarding** (currently just logs connections)
- **UDP proxy** functionality
- **HTTPS proxy** functionality
- **Plugin system** integration
- **Advanced authentication** methods (OIDC)
- **Connection pooling** optimization

## Web Management Interfaces

### Server Web Interface

- **URL**: http://localhost:7500
- **Default credentials**: admin / admin
- **Features**: Server metrics, controller list, proxy list

### Client Web Interface

- **URL**: http://localhost:7400
- **Default credentials**: admin / admin
- **Features**: Proxy list, visitor list

## Security Considerations

1. **TLS Encryption**: Enable TLS in the transport configuration to secure communications
2. **Strong Authentication**: Use a secure token for authentication
3. **Web Interface Security**: Change the default credentials for web interfaces
4. **Port Security**: Only expose necessary ports to the public
5. **Regular Updates**: Keep the project updated to address security vulnerabilities

## Troubleshooting

### Common Issues

1. **Cargo build failures**
   - Ensure Rust and Cargo are up to date
   - Check for OpenSSL development libraries
   - Clear Cargo cache with `cargo clean`

2. **Connection issues**
   - Verify firewall settings
   - Check network connectivity between client and server
   - Ensure the server is running and accessible

3. **Authentication failures**
   - Verify the token is correct in both client and server configurations
   - Check the authentication method is consistent

## Future Development

1. **Complete proxy forwarding** implementation
2. **Add UDP and HTTPS proxy** support
3. **Implement plugin system** for extensibility
4. **Add more authentication methods**
5. **Optimize performance** with connection pooling and other techniques
6. **Add more configuration options** and flexibility

## License

MIT License