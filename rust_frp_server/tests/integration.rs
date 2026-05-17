use rust_frp_config::PortRange;
use rust_frp_server::ServerError;

#[test]
fn test_server_error_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ServerError>();
}

#[test]
fn test_server_error_display() {
    let err = ServerError::ProxyNotFound("myproxy".to_string());
    assert!(format!("{}", err).contains("myproxy"));

    let err = ServerError::PortNotAllowed(9999);
    assert!(format!("{}", err).contains("9999"));

    let err = ServerError::Other("something went wrong".to_string());
    assert!(format!("{}", err).contains("something went wrong"));
}

#[test]
fn test_server_error_from_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "test");
    let server_err: ServerError = io_err.into();
    assert!(format!("{}", server_err).contains("I/O error"));
}

#[test]
fn test_port_range_default() {
    let pr = PortRange::default();
    assert_eq!(pr.single, None);
    assert_eq!(pr.start, None);
    assert_eq!(pr.end, None);
}
