// FFI bindings for use in other languages

use std::{
    os::raw::{c_char, c_int, c_uint},
    str::FromStr,
};

use crate::{
    config::{self},
    events::Bus,
    start_tunnels,
};

/// Starts a new onetun tunnel
/// # Arguments
/// * `config` - The configuration for the tunnel, generated with `onetun_new_config`
/// * `bus` - The bus to publish events on, generated with `onetun_new_bus`
/// # Returns
/// 0 on success, non-zero on failure
/// # Safety
/// All pointers must be valid and not null.
#[no_mangle]
pub unsafe extern "C" fn onetun_start_tunnels(config: *mut config::Config, bus: *mut Bus) -> i32 {
    // Unbox the structs
    let config = *(std::boxed::Box::from_raw(config));
    let bus = *(std::boxed::Box::from_raw(bus));

    // Create a runtime for the future
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            error!("Failed to create runtime: {}", err);
            return -1;
        }
    };

    // Start the future
    rt.block_on(async move {
        match start_tunnels(config, bus).await {
            Ok(_) => 0,
            Err(err) => {
                error!("Failed to start tunnels: {}", err);
                -1
            }
        }
    });
    0
}

/// Creates a new config struct for starting a tunnel
/// # Arguments
/// * `port_forwards` - A pointer to an array of pointers to port forwards, generated with `onetun_new_port_forward`
/// * `port_forwards_len` - The length of the array of pointers to port forwards
/// * `remote_forwards` - A pointer to an array of pointers to port forwards, generated with `onetun_new_port_forward`
/// * `remote_forwards_len` - The length of the array of pointers to port forwards
/// * `private_key` - A pointer to an array of chars containing the private key
/// * `public_key` - A pointer to an array of chars containing the public key
/// * `endpoint_addr` - A pointer to an array of chars containing the endpoint address
/// * `endpoint_bind_addr` - A pointer to an array of chars containing the endpoint bind address
/// * `source_peer_ip` - A pointer to an array of chars containing the source peer IP address
/// * `keepalive_seconds` - A number representing the keepalive interval, or -1 for None
/// * `max_transmission_unit` - A number representing the maximum transmission unit
/// * `log` - A pointer to an array of chars containing the log level (e.g. "INFO", "DEBUG", "TRACE")
/// * `pcap_file` - A pointer to an array of chars containing the pcap file path, or NULL for none
/// # Returns
/// A pointer to a config struct, or NULL on failure
/// # Safety
/// All pointers must be valid and not null, unless specified and expected to be NULL.
#[no_mangle]
pub unsafe extern "C" fn onetun_new_config(
    port_forwards: *const *mut config::PortForwardConfig,
    port_forwards_len: c_uint,
    remote_forwards: *const *mut config::PortForwardConfig,
    remote_forwards_len: c_uint,
    private_key: *const c_char,
    public_key: *const c_char,
    endpoint_addr: *const c_char,
    endpoint_bind_addr: *const c_char,
    source_peer_ip: *const c_char,
    keepalive_seconds: c_int,
    max_transmission_unit: c_int,
    log: *const c_char,
    pcap_file: *const c_char,
) -> *mut config::Config {
    // Convert the port configs to a vector of PortForwardConfigs ending with a null pointer
    let port_forwards = std::slice::from_raw_parts(port_forwards, port_forwards_len as usize)
        .iter()
        .filter(|&&x| !x.is_null())
        .map(|&x| *(std::boxed::Box::from_raw(x)))
        .collect::<Vec<_>>();
    let remote_forwards = std::slice::from_raw_parts(remote_forwards, remote_forwards_len as usize)
        .iter()
        .filter(|&&x| !x.is_null())
        .map(|&x| *(std::boxed::Box::from_raw(x)))
        .collect::<Vec<_>>();

    // Convert the c_chars to &str's
    let private_key = match std::ffi::CStr::from_ptr(private_key).to_str() {
        Ok(x) => match config::X25519SecretKey::from_str(x) {
            Ok(x) => x,
            Err(e) => {
                println!("Error parsing private key: {}", e);
                return std::ptr::null_mut();
            }
        },
        Err(_) => return std::ptr::null_mut(),
    };
    let public_key = match std::ffi::CStr::from_ptr(public_key).to_str() {
        Ok(x) => match config::X25519PublicKey::from_str(x) {
            Ok(x) => x,
            Err(e) => {
                println!("Error parsing public key: {}", e);
                return std::ptr::null_mut();
            }
        },
        Err(_) => return std::ptr::null_mut(),
    };
    let endpoint_addr = match std::ffi::CStr::from_ptr(endpoint_addr).to_str() {
        Ok(x) => match config::parse_addr(Some(x)) {
            Ok(x) => x,
            Err(e) => {
                println!("Error parsing endpoint address: {}", e);
                return std::ptr::null_mut();
            }
        },
        Err(_) => return std::ptr::null_mut(),
    };
    let endpoint_bind_addr = match std::ffi::CStr::from_ptr(endpoint_bind_addr).to_str() {
        Ok(x) => match config::parse_addr(Some(x)) {
            Ok(x) => x,
            Err(e) => {
                println!("Error parsing endpoint bind address: {}", e);
                return std::ptr::null_mut();
            }
        },
        Err(_) => return std::ptr::null_mut(),
    };
    let source_peer_ip = match std::ffi::CStr::from_ptr(source_peer_ip).to_str() {
        Ok(x) => match config::parse_ip(Some(x)) {
            Ok(x) => x,
            Err(e) => {
                println!("Error parsing source peer IP: {}", e);
                return std::ptr::null_mut();
            }
        },
        Err(_) => return std::ptr::null_mut(),
    };
    let log = match std::ffi::CStr::from_ptr(log).to_str() {
        Ok(x) => x.to_string(),
        Err(_) => return std::ptr::null_mut(),
    };

    let pcap_file = if pcap_file.is_null() {
        None
    } else {
        match std::ffi::CStr::from_ptr(pcap_file).to_str() {
            Ok(x) => Some(x.to_string()),
            Err(_) => return std::ptr::null_mut(),
        }
    };

    let keepalive_seconds = if keepalive_seconds == -1 {
        None
    } else {
        Some(keepalive_seconds as u16)
    };

    // Create the config
    let config = config::Config {
        port_forwards,
        remote_port_forwards: remote_forwards,
        private_key: std::sync::Arc::new(private_key),
        endpoint_public_key: std::sync::Arc::new(public_key),
        endpoint_addr,
        endpoint_bind_addr,
        source_peer_ip,
        keepalive_seconds,
        max_transmission_unit: max_transmission_unit as usize,
        log,
        pcap_file,
        warnings: vec![],
    };

    // Return a pointer to the config
    Box::into_raw(Box::new(config)) as *mut config::Config
}

/// Creates a new bus struct
/// # Arguments
/// *none*
/// # Returns
/// A pointer to a bus struct
#[no_mangle]
pub extern "C" fn onetun_new_bus() -> *mut Bus {
    let bus = Bus::new();
    Box::into_raw(Box::new(bus)) as *mut Bus
}

/// Creates a new port forward configuration
/// # Arguments
/// * `source` - A list of chars representing a socket address
/// * `destination` - A list of chars representing a socket address
/// * `protocol` - Either `tcp` or `udp`
/// * `port` - Whether this forward is remote: 1 for true, 0 for false
/// # Returns
/// A pointer to a port forward config struct, or NULL on failure
/// # Safety
/// All pointers must be valid. Strings may be freed after this function returns.
#[no_mangle]
pub unsafe extern "C" fn onetun_new_port_forward(
    source: *const c_char,
    destination: *const c_char,
    protocol: *const c_char,
    remote: c_uint,
) -> *mut config::PortForwardConfig {
    // Create strings from pointers
    let source = match std::ffi::CStr::from_ptr(source).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let destination = match std::ffi::CStr::from_ptr(destination).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let protocol = match std::ffi::CStr::from_ptr(protocol).to_str() {
        Ok(s) => s.to_lowercase(),
        Err(_) => return std::ptr::null_mut(),
    };

    // Create config
    let config = config::PortForwardConfig {
        source: std::net::SocketAddr::V4(match std::net::SocketAddrV4::from_str(source) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }),
        destination: std::net::SocketAddr::V4(
            match std::net::SocketAddrV4::from_str(destination) {
                Ok(s) => s,
                Err(_) => return std::ptr::null_mut(),
            },
        ),
        protocol: match protocol.as_str() {
            "tcp" => config::PortProtocol::Tcp,
            "udp" => config::PortProtocol::Udp,
            _ => return std::ptr::null_mut(),
        },
        remote: remote == 1,
    };

    // Create pointer to config
    let config = Box::new(config);
    Box::into_raw(config) as *mut config::PortForwardConfig
}
