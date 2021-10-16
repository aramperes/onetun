use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use anyhow::Context;
use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use clap::{App, Arg};

#[derive(Clone, Debug)]
pub struct Config {
    pub(crate) source_addr: SocketAddr,
    pub(crate) dest_addr: SocketAddr,
    pub(crate) private_key: Arc<X25519SecretKey>,
    pub(crate) endpoint_public_key: Arc<X25519PublicKey>,
    pub(crate) endpoint_addr: SocketAddr,
    pub(crate) source_peer_ip: IpAddr,
    pub(crate) keepalive_seconds: Option<u16>,
    pub(crate) log: String,
}

impl Config {
    pub fn from_args() -> anyhow::Result<Self> {
        let matches = App::new("onetun")
            .author("Aram Peres <aram.peres@gmail.com>")
            .version(env!("CARGO_PKG_VERSION"))
            .args(&[
                Arg::with_name("SOURCE_ADDR")
                    .required(true)
                    .takes_value(true)
                    .env("ONETUN_SOURCE_ADDR")
                    .help("The source address (IP + port) to forward from. Example: 127.0.0.1:2115"),
                Arg::with_name("DESTINATION_ADDR")
                    .required(true)
                    .takes_value(true)
                    .env("ONETUN_DESTINATION_ADDR")
                    .help("The destination address (IP + port) to forward to. The IP should be a peer registered in the Wireguard endpoint. Example: 192.168.4.2:2116"),
                Arg::with_name("private-key")
                    .required(true)
                    .takes_value(true)
                    .long("private-key")
                    .env("ONETUN_PRIVATE_KEY")
                    .help("The private key of this peer. The corresponding public key should be registered in the Wireguard endpoint."),
                Arg::with_name("endpoint-public-key")
                    .required(true)
                    .takes_value(true)
                    .long("endpoint-public-key")
                    .env("ONETUN_ENDPOINT_PUBLIC_KEY")
                    .help("The public key of the Wireguard endpoint (remote)."),
                Arg::with_name("endpoint-addr")
                    .required(true)
                    .takes_value(true)
                    .long("endpoint-addr")
                    .env("ONETUN_ENDPOINT_ADDR")
                    .help("The address (IP + port) of the Wireguard endpoint (remote). Example: 1.2.3.4:51820"),
                Arg::with_name("source-peer-ip")
                    .required(true)
                    .takes_value(true)
                    .long("source-peer-ip")
                    .env("ONETUN_SOURCE_PEER_IP")
                    .help("The source IP to identify this peer as (local). Example: 192.168.4.3"),
                Arg::with_name("keep-alive")
                    .required(false)
                    .takes_value(true)
                    .long("keep-alive")
                    .env("ONETUN_KEEP_ALIVE")
                    .help("Configures a persistent keep-alive for the WireGuard tunnel, in seconds."),
                Arg::with_name("log")
                    .required(false)
                    .takes_value(true)
                    .long("log")
                    .env("ONETUN_LOG")
                    .default_value("info")
                    .help("Configures the log level and format.")
            ]).get_matches();

        Ok(Self {
            source_addr: parse_addr(matches.value_of("SOURCE_ADDR"))
                .with_context(|| "Invalid source address")?,
            dest_addr: parse_addr(matches.value_of("DESTINATION_ADDR"))
                .with_context(|| "Invalid destination address")?,
            private_key: Arc::new(
                parse_private_key(matches.value_of("private-key"))
                    .with_context(|| "Invalid private key")?,
            ),
            endpoint_public_key: Arc::new(
                parse_public_key(matches.value_of("endpoint-public-key"))
                    .with_context(|| "Invalid endpoint public key")?,
            ),
            endpoint_addr: parse_addr(matches.value_of("endpoint-addr"))
                .with_context(|| "Invalid endpoint address")?,
            source_peer_ip: parse_ip(matches.value_of("source-peer-ip"))
                .with_context(|| "Invalid source peer IP")?,
            keepalive_seconds: parse_keep_alive(matches.value_of("keep-alive"))
                .with_context(|| "Invalid keep-alive value")?,
            log: matches.value_of("log").unwrap_or_default().into(),
        })
    }
}

fn parse_addr(s: Option<&str>) -> anyhow::Result<SocketAddr> {
    s.with_context(|| "Missing address")?
        .to_socket_addrs()
        .with_context(|| "Invalid address")?
        .next()
        .with_context(|| "Could not lookup address")
}

fn parse_ip(s: Option<&str>) -> anyhow::Result<IpAddr> {
    s.with_context(|| "Missing IP")?
        .parse::<IpAddr>()
        .with_context(|| "Invalid IP address")
}

fn parse_private_key(s: Option<&str>) -> anyhow::Result<X25519SecretKey> {
    s.with_context(|| "Missing private key")?
        .parse::<X25519SecretKey>()
        .map_err(|e| anyhow::anyhow!("{}", e))
        .with_context(|| "Invalid private key")
}

fn parse_public_key(s: Option<&str>) -> anyhow::Result<X25519PublicKey> {
    s.with_context(|| "Missing public key")?
        .parse::<X25519PublicKey>()
        .map_err(|e| anyhow::anyhow!("{}", e))
        .with_context(|| "Invalid public key")
}

fn parse_keep_alive(s: Option<&str>) -> anyhow::Result<Option<u16>> {
    if let Some(s) = s {
        let parsed: u16 = s.parse().with_context(|| {
            format!(
                "Keep-alive must be a number between 0 and {} seconds",
                u16::MAX
            )
        })?;
        Ok(Some(parsed))
    } else {
        Ok(None)
    }
}
