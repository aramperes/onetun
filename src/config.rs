use std::collections::HashSet;
use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use anyhow::Context;
use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use clap::{App, Arg};

#[derive(Clone, Debug)]
pub struct Config {
    pub(crate) port_forwards: Vec<PortForwardConfig>,
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
                Arg::with_name("PORT_FORWARD")
                    .required(false)
                    .multiple(true)
                    .takes_value(true)
                    .help("Port forward configurations. The format of each argument is [src_host:]<src_port>:<dst_host>:<dst_port>[:TCP,UDP,...]. \
                    Environment variables of the form 'ONETUN_PORT_FORWARD_[#]' are also accepted, where [#] starts at 1."),
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

        // Combine `PORT_FORWARD` arg and `ONETUN_PORT_FORWARD_#` strings
        let mut port_forward_strings = HashSet::new();
        matches.values_of("PORT_FORWARD").map(|values| {
            values
                .into_iter()
                .map(|v| port_forward_strings.insert(v.to_string()))
                .map(|_| ())
        });
        for n in 1.. {
            if let Ok(env) = std::env::var(format!("ONETUN_PORT_FORWARD_{}", n)) {
                port_forward_strings.insert(env);
            } else {
                break;
            }
        }
        if port_forward_strings.is_empty() {
            return Err(anyhow::anyhow!("No port forward configurations given."));
        }

        // Parse `PORT_FORWARD` strings into `PortForwardConfig`
        let port_forwards: Vec<anyhow::Result<Vec<PortForwardConfig>>> = port_forward_strings
            .into_iter()
            .map(|s| PortForwardConfig::from_str(&s))
            .collect();
        let port_forwards: anyhow::Result<Vec<Vec<PortForwardConfig>>> =
            port_forwards.into_iter().collect();
        let port_forwards: Vec<PortForwardConfig> = port_forwards
            .with_context(|| "Failed to parse port forward config")?
            .into_iter()
            .flatten()
            .collect();

        Ok(Self {
            port_forwards,
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

#[derive(Debug, Clone, Copy)]
pub struct PortForwardConfig {
    /// The source IP and port where the local server will run.
    pub source: SocketAddr,
    /// The destination IP and port to which traffic will be forwarded.
    pub destination: SocketAddr,
    /// The transport protocol to use for the port (Layer 4).
    pub protocol: PortProtocol,
}

impl PortForwardConfig {
    /// Converts a string representation into `PortForwardConfig`.
    ///
    /// Sample formats:
    ///  - `127.0.0.1:8080:192.168.4.1:8081:TCP,UDP`
    ///  - `127.0.0.1:8080:192.168.4.1:8081:TCP`
    ///  - `0.0.0.0:8080:192.168.4.1:8081`
    ///  - `[::1]:8080:192.168.4.1:8081`
    ///  - `8080:192.168.4.1:8081`
    ///  - `8080:192.168.4.1:8081:TCP`
    ///
    /// Implementation Notes:
    ///  - The format is formalized as `[src_host:]<src_port>:<dst_host>:<dst_port>[:PROTO1,PROTO2,...]`
    ///  - `src_host` is optional and defaults to `127.0.0.1`.
    ///  - `src_host` and `dst_host` may be specified as IPv4, IPv6, or a FQDN to be resolved by DNS.
    ///  - IPv6 addresses must be prefixed with `[` and suffixed with `]`. Example: `[::1]`.
    ///  - Any `u16` is accepted as `src_port` and `dst_port`
    ///  - Specifying protocols (`PROTO1,PROTO2,...`) is optional and defaults to `TCP`. Values must be separated by commas.
    pub fn from_str<'a>(s: &'a str) -> anyhow::Result<Vec<PortForwardConfig>> {
        use nom::branch::alt;
        use nom::bytes::complete::{is_not, take_until, take_while};
        use nom::character::complete::char;
        use nom::combinator::opt;
        use nom::multi::separated_list0;
        use nom::sequence::{delimited, terminated};
        use nom::IResult;

        Err(anyhow::anyhow!("TODO"))
    }
}

impl Display for PortForwardConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.source, self.destination, self.protocol)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PortProtocol {
    Tcp,
    Udp,
}

impl TryFrom<&str> for PortProtocol {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> anyhow::Result<Self> {
        match value.to_uppercase().as_str() {
            "TCP" => Ok(Self::Tcp),
            "UDP" => Ok(Self::Udp),
            _ => Err(anyhow::anyhow!("Invalid protocol specifier: {}", value)),
        }
    }
}

impl Display for PortProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Tcp => "TCP",
                Self::Udp => "UDP",
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests the parsing of `PortForwardConfig`.
    fn test_parse_port_forward_config() {}
}
