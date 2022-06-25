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

#[no_mangle]
pub extern "C" fn onetun_start_tunnels(config: *mut config::Config, bus: *mut Bus) -> i32 {
    // Unbox the structs
    let config = unsafe { *(std::boxed::Box::from_raw(config)) };
    let bus = unsafe { *(std::boxed::Box::from_raw(bus)) };

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

#[no_mangle]
pub extern "C" fn onetun_new_config(
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
    let port_forwards = unsafe {
        std::slice::from_raw_parts(port_forwards, port_forwards_len as usize)
            .iter()
            .filter(|&&x| (!x.is_null() || x != 0 as *mut _))
            .map(|&x| *(std::boxed::Box::from_raw(x)))
            .map(|x| x.clone())
            .collect::<Vec<_>>()
    };
    let remote_forwards = unsafe {
        std::slice::from_raw_parts(remote_forwards, remote_forwards_len as usize)
            .iter()
            .filter(|&&x| (!x.is_null() || x != 0 as *mut _))
            .map(|&x| *(std::boxed::Box::from_raw(x)))
            .map(|x| x.clone())
            .collect::<Vec<_>>()
    };

    // Convert the c_chars to &str's
    let private_key = unsafe {
        match std::ffi::CStr::from_ptr(private_key).to_str() {
            Ok(x) => match config::X25519SecretKey::from_str(x) {
                Ok(x) => x,
                Err(e) => {
                    println!("Error parsing private key: {}", e);
                    return std::ptr::null_mut();
                }
            },
            Err(_) => return std::ptr::null_mut(),
        }
    };
    let public_key = unsafe {
        match std::ffi::CStr::from_ptr(public_key).to_str() {
            Ok(x) => match config::X25519PublicKey::from_str(x) {
                Ok(x) => x,
                Err(e) => {
                    println!("Error parsing public key: {}", e);
                    return std::ptr::null_mut();
                }
            },
            Err(_) => return std::ptr::null_mut(),
        }
    };
    let endpoint_addr = unsafe {
        match std::ffi::CStr::from_ptr(endpoint_addr).to_str() {
            Ok(x) => match config::parse_addr(Some(x)) {
                Ok(x) => x,
                Err(e) => {
                    println!("Error parsing endpoint address: {}", e);
                    return std::ptr::null_mut();
                }
            },
            Err(_) => return std::ptr::null_mut(),
        }
    };
    let endpoint_bind_addr = unsafe {
        match std::ffi::CStr::from_ptr(endpoint_bind_addr).to_str() {
            Ok(x) => match config::parse_addr(Some(x)) {
                Ok(x) => x,
                Err(e) => {
                    println!("Error parsing endpoint bind address: {}", e);
                    return std::ptr::null_mut();
                }
            },
            Err(_) => return std::ptr::null_mut(),
        }
    };
    let source_peer_ip = unsafe {
        match std::ffi::CStr::from_ptr(source_peer_ip).to_str() {
            Ok(x) => match config::parse_ip(Some(x)) {
                Ok(x) => x,
                Err(e) => {
                    println!("Error parsing source peer IP: {}", e);
                    return std::ptr::null_mut();
                }
            },
            Err(_) => return std::ptr::null_mut(),
        }
    };
    let log = unsafe {
        match std::ffi::CStr::from_ptr(log).to_str() {
            Ok(x) => x.to_string(),
            Err(_) => return std::ptr::null_mut(),
        }
    };
    let pcap_file = unsafe {
        match std::ffi::CStr::from_ptr(pcap_file).to_str() {
            Ok(x) => {
                if x == "" {
                    None
                } else {
                    Some(x.to_string())
                }
            }
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

#[no_mangle]
pub extern "C" fn onetun_new_bus() -> *mut Bus {
    let bus = Bus::new();
    Box::into_raw(Box::new(bus)) as *mut Bus
}

#[no_mangle]
pub extern "C" fn onetun_new_port_forward(
    source: *const c_char,
    destination: *const c_char,
    protocol: *const c_char,
    remote: c_uint,
) -> *mut config::PortForwardConfig {
    // Create strings from pointers
    let source = unsafe {
        match std::ffi::CStr::from_ptr(source).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }
    };
    let destination = unsafe {
        match std::ffi::CStr::from_ptr(destination).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }
    };
    let protocol = unsafe {
        match std::ffi::CStr::from_ptr(protocol).to_str() {
            Ok(s) => s.to_lowercase(),
            Err(_) => return std::ptr::null_mut(),
        }
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
        remote: remote == 0,
    };

    // Create pointer to config
    let config = Box::new(config);
    Box::into_raw(config) as *mut config::PortForwardConfig
}
