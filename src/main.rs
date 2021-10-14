#[macro_use]
extern crate log;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::io::Interest;
use tokio::net::{TcpListener, TcpStream};

use crate::config::Config;
use crate::port_pool::PortPool;
use crate::wg::WireGuardTunnel;

pub mod client;
pub mod config;
pub mod port_pool;
pub mod virtual_device;
pub mod wg;

pub const MAX_PACKET: usize = 65536;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pretty_env_logger::init_custom_env("ONETUN_LOG");
    let config = Config::from_args().with_context(|| "Failed to read config")?;
    let port_pool = Arc::new(PortPool::new());

    let wg = WireGuardTunnel::new(&config)
        .await
        .with_context(|| "Failed to initialize WireGuard tunnel")?;
    let wg = Arc::new(wg);

    {
        // Start routine task for WireGuard
        let wg = wg.clone();
        tokio::spawn(async move { wg.routine_task().await });
    }

    {
        // Start consumption task for WireGuard
        let wg = wg.clone();
        tokio::spawn(async move { wg.consume_task().await });
    }

    info!(
        "Tunnelling [{}]->[{}] (via [{}] as peer {})",
        &config.source_addr, &config.dest_addr, &config.endpoint_addr, &config.source_peer_ip
    );

    tcp_proxy_server(config.source_addr.clone(), port_pool.clone(), wg).await
}

/// Starts the server that listens on TCP connections.
async fn tcp_proxy_server(
    listen_addr: SocketAddr,
    port_pool: Arc<PortPool>,
    wg: Arc<WireGuardTunnel>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| "Failed to listen on TCP proxy server")?;

    loop {
        let wg = wg.clone();
        let port_pool = port_pool.clone();
        let (socket, peer_addr) = listener
            .accept()
            .await
            .with_context(|| "Failed to accept connection on TCP proxy server")?;

        // Assign a 'virtual port': this is a unique port number used to route IP packets
        // received from the WireGuard tunnel. It is the port number that the virtual client will
        // listen on.
        let virtual_port = match port_pool.next() {
            Ok(port) => port,
            Err(e) => {
                error!(
                    "Failed to assign virtual port number for connection [{}]: {:?}",
                    peer_addr, e
                );
                continue;
            }
        };

        info!("[{}] Incoming connection from {}", virtual_port, peer_addr);

        tokio::spawn(async move {
            let port_pool = Arc::clone(&port_pool);
            let result = handle_tcp_proxy_connection(socket, virtual_port, wg).await;

            if let Err(e) = result {
                error!(
                    "[{}] Connection dropped un-gracefully: {:?}",
                    virtual_port, e
                );
            } else {
                info!("[{}] Connection closed by client", virtual_port);
            }

            // Release port when connection drops
            port_pool.release(virtual_port);
        });
    }
}

/// Handles a new TCP connection with its assigned virtual port.
async fn handle_tcp_proxy_connection(
    socket: TcpStream,
    virtual_port: u16,
    wg: Arc<WireGuardTunnel>,
) -> anyhow::Result<()> {
    let abort = Arc::new(AtomicBool::new(false));

    // Spawn virtual interface
    {
        let abort = abort.clone();
        tokio::spawn(async move { virtual_tcp_interface(virtual_port, wg, abort).await });
    }

    loop {
        let ready = socket
            .ready(Interest::READABLE | Interest::WRITABLE)
            .await
            .with_context(|| "Failed to wait for TCP proxy socket readiness")?;

        if abort.load(Ordering::Relaxed) {
            break;
        }

        if ready.is_readable() {
            let mut buffer = [0u8; MAX_PACKET];

            match socket.try_read(&mut buffer) {
                Ok(size) if size > 0 => {
                    let data = &buffer[..size];
                    debug!(
                        "[{}] Read {} bytes of TCP data from real client",
                        virtual_port, size
                    );
                    trace!("[{}] {:?}", virtual_port, data);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    error!(
                        "[{}] Failed to read from client TCP socket: {:?}",
                        virtual_port, e
                    );
                    break;
                }
                _ => {}
            }
        }

        if ready.is_writable() {}

        if ready.is_read_closed() || ready.is_write_closed() {
            break;
        }
    }

    trace!("[{}] TCP socket handler task terminated", virtual_port);
    abort.store(true, Ordering::Relaxed);
    Ok(())
}

async fn virtual_tcp_interface(
    virtual_port: u16,
    wg: Arc<WireGuardTunnel>,
    abort: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    loop {
        if abort.load(Ordering::Relaxed) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    trace!("[{}] Virtual interface task terminated", virtual_port);
    Ok(())
}
