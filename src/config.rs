use std::collections::HashSet;
use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
use std::fs::read_to_string;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use anyhow::Context;
use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use clap::{App, Arg};

const DEFAULT_PORT_FORWARD_SOURCE: &str = "127.0.0.1";

#[derive(Clone, Debug)]
pub struct Config {
    pub(crate) port_forwards: Vec<PortForwardConfig>,
    #[allow(dead_code)]
    pub(crate) remote_port_forwards: Vec<PortForwardConfig>,
    pub(crate) private_key: Arc<X25519SecretKey>,
    pub(crate) endpoint_public_key: Arc<X25519PublicKey>,
    pub(crate) endpoint_addr: SocketAddr,
    pub(crate) endpoint_bind_addr: SocketAddr,
    pub(crate) source_peer_ip: IpAddr,
    pub(crate) keepalive_seconds: Option<u16>,
    pub(crate) max_transmission_unit: usize,
    pub(crate) log: String,
    pub(crate) warnings: Vec<String>,
    pub(crate) pcap_file: Option<String>,
}

impl Config {
    pub fn from_args() -> anyhow::Result<Self> {
        let mut warnings = vec![];

        let matches = App::new("onetun")
            .author("Aram Peres <aram.peres@gmail.com>")
            .version(env!("CARGO_PKG_VERSION"))
            .args(&[
                Arg::with_name("PORT_FORWARD")
                    .required(false)
                    .multiple(true)
                    .takes_value(true)
                    .help("Port forward configurations. The format of each argument is [src_host:]<src_port>:<dst_host>:<dst_port>[:TCP,UDP,...], \
                    where [src_host] is the local IP to listen on, <src_port> is the local port to listen on, <dst_host> is the remote peer IP to forward to, and <dst_port> is the remote port to forward to. \
                    Environment variables of the form 'ONETUN_PORT_FORWARD_[#]' are also accepted, where [#] starts at 1.\n\
                    Examples:\n\
                    \t127.0.0.1:8080:192.168.4.1:8081:TCP,UDP\n\
                    \t127.0.0.1:8080:192.168.4.1:8081:TCP\n\
                    \t0.0.0.0:8080:192.168.4.1:8081\n\
                    \t[::1]:8080:192.168.4.1:8081\n\
                    \t8080:192.168.4.1:8081\n\
                    \t8080:192.168.4.1:8081:TCP\n\
                    \tlocalhost:8080:192.168.4.1:8081:TCP\n\
                    \tlocalhost:8080:peer.intranet:8081:TCP\
                    "),
                Arg::with_name("private-key")
                    .required_unless("private-key-file")
                    .takes_value(true)
                    .long("private-key")
                    .env("ONETUN_PRIVATE_KEY")
                    .help("The private key of this peer. The corresponding public key should be registered in the WireGuard endpoint. \
                    You can also use '--private-key-file' to specify a file containing the key instead."),
                Arg::with_name("private-key-file")
                    .takes_value(true)
                    .long("private-key-file")
                    .env("ONETUN_PRIVATE_KEY_FILE")
                    .help("The path to a file containing the private key of this peer. The corresponding public key should be registered in the WireGuard endpoint."),
                Arg::with_name("endpoint-public-key")
                    .required(true)
                    .takes_value(true)
                    .long("endpoint-public-key")
                    .env("ONETUN_ENDPOINT_PUBLIC_KEY")
                    .help("The public key of the WireGuard endpoint (remote)."),
                Arg::with_name("endpoint-addr")
                    .required(true)
                    .takes_value(true)
                    .long("endpoint-addr")
                    .env("ONETUN_ENDPOINT_ADDR")
                    .help("The address (IP + port) of the WireGuard endpoint (remote). Example: 1.2.3.4:51820"),
                Arg::with_name("endpoint-bind-addr")
                    .required(false)
                    .takes_value(true)
                    .long("endpoint-bind-addr")
                    .env("ONETUN_ENDPOINT_BIND_ADDR")
                    .help("The address (IP + port) used to bind the local UDP socket for the WireGuard tunnel. Example: 1.2.3.4:30000. Defaults to 0.0.0.0:0 for IPv4 endpoints, or [::]:0 for IPv6 endpoints."),
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
                Arg::with_name("max-transmission-unit")
                    .required(false)
                    .takes_value(true)
                    .long("max-transmission-unit")
                    .env("ONETUN_MTU")
                    .default_value("1420")
                    .help("Configures the max-transmission-unit (MTU) of the WireGuard tunnel."),
                Arg::with_name("log")
                    .required(false)
                    .takes_value(true)
                    .long("log")
                    .env("ONETUN_LOG")
                    .default_value("info")
                    .help("Configures the log level and format."),
                Arg::with_name("pcap")
                    .required(false)
                    .takes_value(true)
                    .long("pcap")
                    .env("ONETUN_PCAP")
                    .help("Decrypts and captures IP packets on the WireGuard tunnel to a given output file."),
                Arg::with_name("remote")
                    .required(false)
                    .takes_value(true)
                    .multiple(true)
                    .long("remote")
                    .short("r")
                    .help("Remote port forward configurations. The format of each argument is <src_port>:<dst_host>:<dst_port>[:TCP,UDP,...], \
                    where <src_port> is the port the other peers will reach the server with, <dst_host> is the IP to forward to, and <dst_port> is the port to forward to. \
                    The <src_port> will be bound on onetun's peer IP, as specified by --source-peer-ip. If you pass a different value for <src_host> here, it will be rejected.\n\
                    Note: <dst_host>:<dst_port> must be reachable by onetun. If referring to another WireGuard peer, use --bridge instead (not supported yet).\n\
                    Environment variables of the form 'ONETUN_REMOTE_PORT_FORWARD_[#]' are also accepted, where [#] starts at 1.\n\
                    Examples:\n\
                    \t--remote 8080:localhost:8081:TCP,UDP\n\
                    \t--remote 8080:[::1]:8081:TCP\n\
                    \t--remote 8080:google.com:80\
                    "),
            ]).get_matches();

        // Combine `PORT_FORWARD` arg and `ONETUN_PORT_FORWARD_#` envs
        let mut port_forward_strings = HashSet::new();
        if let Some(values) = matches.values_of("PORT_FORWARD") {
            for value in values {
                port_forward_strings.insert(value.to_owned());
            }
        }
        for n in 1.. {
            if let Ok(env) = std::env::var(format!("ONETUN_PORT_FORWARD_{}", n)) {
                port_forward_strings.insert(env);
            } else {
                break;
            }
        }

        // Parse `PORT_FORWARD` strings into `PortForwardConfig`
        let port_forwards: anyhow::Result<Vec<Vec<PortForwardConfig>>> = port_forward_strings
            .into_iter()
            .map(|s| PortForwardConfig::from_notation(&s, DEFAULT_PORT_FORWARD_SOURCE))
            .collect();
        let port_forwards: Vec<PortForwardConfig> = port_forwards
            .with_context(|| "Failed to parse port forward config")?
            .into_iter()
            .flatten()
            .collect();

        // Read source-peer-ip
        let source_peer_ip = parse_ip(matches.value_of("source-peer-ip"))
            .with_context(|| "Invalid source peer IP")?;

        // Combined `remote` arg and `ONETUN_REMOTE_PORT_FORWARD_#` envs
        let mut port_forward_strings = HashSet::new();
        if let Some(values) = matches.values_of("remote") {
            for value in values {
                port_forward_strings.insert(value.to_owned());
            }
        }
        for n in 1.. {
            if let Ok(env) = std::env::var(format!("ONETUN_REMOTE_PORT_FORWARD_{}", n)) {
                port_forward_strings.insert(env);
            } else {
                break;
            }
        }
        // Parse `PORT_FORWARD` strings into `PortForwardConfig`
        let remote_port_forwards: anyhow::Result<Vec<Vec<PortForwardConfig>>> =
            port_forward_strings
                .into_iter()
                .map(|s| {
                    PortForwardConfig::from_notation(
                        &s,
                        matches.value_of("source-peer-ip").unwrap(),
                    )
                })
                .collect();
        let mut remote_port_forwards: Vec<PortForwardConfig> = remote_port_forwards
            .with_context(|| "Failed to parse remote port forward config")?
            .into_iter()
            .flatten()
            .collect();
        for port_forward in remote_port_forwards.iter_mut() {
            if port_forward.source.ip() != source_peer_ip {
                return Err(anyhow::anyhow!("Remote port forward config <src_host> must match --source-peer-ip ({}), or be omitted.", source_peer_ip));
            }
            port_forward.source = SocketAddr::from((source_peer_ip, port_forward.source.port()));
            port_forward.remote = true;
        }

        if port_forwards.is_empty() && remote_port_forwards.is_empty() {
            return Err(anyhow::anyhow!("No port forward configurations given."));
        }

        // Read private key from file or CLI argument
        let (group_readable, world_readable) = matches
            .value_of("private-key-file")
            .and_then(is_file_insecurely_readable)
            .unwrap_or_default();
        if group_readable {
            warnings.push("Private key file is group-readable. This is insecure.".into());
        }
        if world_readable {
            warnings.push("Private key file is world-readable. This is insecure.".into());
        }

        let private_key = if let Some(private_key_file) = matches.value_of("private-key-file") {
            read_to_string(private_key_file)
                .map(|s| s.trim().to_string())
                .with_context(|| "Failed to read private key file")
        } else {
            if std::env::var("ONETUN_PRIVATE_KEY").is_err() {
                warnings.push("Private key was passed using CLI. This is insecure. \
                Use \"--private-key-file <file containing private key>\", or the \"ONETUN_PRIVATE_KEY\" env variable instead.".into());
            }
            matches
                .value_of("private-key")
                .map(String::from)
                .with_context(|| "Missing private key")
        }?;

        let endpoint_addr = parse_addr(matches.value_of("endpoint-addr"))
            .with_context(|| "Invalid endpoint address")?;

        let endpoint_bind_addr = if let Some(addr) = matches.value_of("endpoint-bind-addr") {
            let addr = parse_addr(Some(addr)).with_context(|| "Invalid host address")?;
            // Make sure the host address and endpoint address are the same IP version
            if addr.ip().is_ipv6() && endpoint_addr.ip().is_ipv6()
                || (addr.ip().is_ipv4() && endpoint_addr.ip().is_ipv4())
            {
                return Err(anyhow::anyhow!(
                    "Host address and endpoint address must be the same IP version"
                ));
            }
            addr
        } else {
            // Return the IP version of the endpoint address
            match endpoint_addr {
                SocketAddr::V4(_) => parse_addr(Some("0.0.0.0:0"))?,
                SocketAddr::V6(_) => parse_addr(Some("[::]:0"))?,
            }
        };

        Ok(Self {
            port_forwards,
            remote_port_forwards,
            private_key: Arc::new(
                parse_private_key(&private_key).with_context(|| "Invalid private key")?,
            ),
            endpoint_public_key: Arc::new(
                parse_public_key(matches.value_of("endpoint-public-key"))
                    .with_context(|| "Invalid endpoint public key")?,
            ),
            endpoint_addr,
            endpoint_bind_addr,
            source_peer_ip,
            keepalive_seconds: parse_keep_alive(matches.value_of("keep-alive"))
                .with_context(|| "Invalid keep-alive value")?,
            max_transmission_unit: parse_mtu(matches.value_of("max-transmission-unit"))
                .with_context(|| "Invalid max-transmission-unit value")?,
            log: matches.value_of("log").unwrap_or_default().into(),
            pcap_file: matches.value_of("pcap").map(String::from),
            warnings,
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

fn parse_private_key(s: &str) -> anyhow::Result<X25519SecretKey> {
    s.parse::<X25519SecretKey>()
        .map_err(|e| anyhow::anyhow!("{}", e))
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

fn parse_mtu(s: Option<&str>) -> anyhow::Result<usize> {
    s.with_context(|| "Missing MTU")?
        .parse()
        .with_context(|| "Invalid MTU")
}

#[cfg(unix)]
fn is_file_insecurely_readable(path: &str) -> Option<(bool, bool)> {
    use std::fs::File;
    use std::os::unix::fs::MetadataExt;

    let mode = File::open(&path).ok()?.metadata().ok()?.mode();
    Some((mode & 0o40 > 0, mode & 0o4 > 0))
}

#[cfg(not(unix))]
fn is_file_insecurely_readable(_path: &str) -> Option<(bool, bool)> {
    // No good way to determine permissions on non-Unix target
    None
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PortForwardConfig {
    /// The source IP and port where the local server will run.
    pub source: SocketAddr,
    /// The destination IP and port to which traffic will be forwarded.
    pub destination: SocketAddr,
    /// The transport protocol to use for the port (Layer 4).
    pub protocol: PortProtocol,
    /// Whether this is a remote port forward.
    pub remote: bool,
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
    ///  - `localhost:8080:192.168.4.1:8081:TCP`
    ///  - `localhost:8080:peer.intranet:8081:TCP`
    ///
    /// Implementation Notes:
    ///  - The format is formalized as `[src_host:]<src_port>:<dst_host>:<dst_port>[:PROTO1,PROTO2,...]`
    ///  - `src_host` is optional and defaults to `127.0.0.1`.
    ///  - `src_host` and `dst_host` may be specified as IPv4, IPv6, or a FQDN to be resolved by DNS.
    ///  - IPv6 addresses must be prefixed with `[` and suffixed with `]`. Example: `[::1]`.
    ///  - Any `u16` is accepted as `src_port` and `dst_port`
    ///  - Specifying protocols (`PROTO1,PROTO2,...`) is optional and defaults to `TCP`. Values must be separated by commas.
    pub fn from_notation(s: &str, default_source: &str) -> anyhow::Result<Vec<PortForwardConfig>> {
        mod parsers {
            use nom::branch::alt;
            use nom::bytes::complete::is_not;
            use nom::character::complete::{alpha1, char, digit1};
            use nom::combinator::{complete, map, opt, success};
            use nom::error::ErrorKind;
            use nom::multi::separated_list1;
            use nom::sequence::{delimited, preceded, separated_pair, tuple};
            use nom::IResult;

            fn ipv6(s: &str) -> IResult<&str, &str> {
                delimited(char('['), is_not("]"), char(']'))(s)
            }

            fn ipv4_or_fqdn(s: &str) -> IResult<&str, &str> {
                let s = is_not(":")(s)?;
                if s.1.chars().all(|c| c.is_ascii_digit()) {
                    // If ipv4 or fqdn is all digits, it's not valid.
                    Err(nom::Err::Error(nom::error::ParseError::from_error_kind(
                        s.1,
                        ErrorKind::Fail,
                    )))
                } else {
                    Ok(s)
                }
            }

            fn port(s: &str) -> IResult<&str, &str> {
                digit1(s)
            }

            fn ip_or_fqdn(s: &str) -> IResult<&str, &str> {
                alt((ipv6, ipv4_or_fqdn))(s)
            }

            fn no_ip(s: &str) -> IResult<&str, Option<&str>> {
                success(None)(s)
            }

            fn src_addr(s: &str) -> IResult<&str, (Option<&str>, &str)> {
                let with_ip = separated_pair(map(ip_or_fqdn, Some), char(':'), port);
                let without_ip = tuple((no_ip, port));
                alt((with_ip, without_ip))(s)
            }

            fn dst_addr(s: &str) -> IResult<&str, (&str, &str)> {
                separated_pair(ip_or_fqdn, char(':'), port)(s)
            }

            fn protocol(s: &str) -> IResult<&str, &str> {
                alpha1(s)
            }

            fn protocols(s: &str) -> IResult<&str, Option<Vec<&str>>> {
                opt(preceded(char(':'), separated_list1(char(','), protocol)))(s)
            }

            #[allow(clippy::type_complexity)]
            pub fn port_forward(
                s: &str,
            ) -> IResult<&str, ((Option<&str>, &str), (), (&str, &str), Option<Vec<&str>>)>
            {
                complete(tuple((
                    src_addr,
                    map(char(':'), |_| ()),
                    dst_addr,
                    protocols,
                )))(s)
            }
        }

        // TODO: Could improve error management with custom errors, so that the messages are more helpful.
        let (src_addr, _, dst_addr, protocols) = parsers::port_forward(s)
            .map_err(|e| anyhow::anyhow!("Invalid port-forward definition: {}", e))?
            .1;

        let source = (
            src_addr.0.unwrap_or(default_source),
            src_addr
                .1
                .parse::<u16>()
                .with_context(|| "Invalid source port")?,
        )
            .to_socket_addrs()
            .with_context(|| "Invalid source address")?
            .next()
            .with_context(|| "Could not resolve source address")?;

        let destination = (
            dst_addr.0,
            dst_addr
                .1
                .parse::<u16>()
                .with_context(|| "Invalid source port")?,
        )
            .to_socket_addrs() // TODO: Pass this as given and use DNS config instead (issue #15)
            .with_context(|| "Invalid destination address")?
            .next()
            .with_context(|| "Could not resolve destination address")?;

        // Parse protocols
        let protocols = if let Some(protocols) = protocols {
            let protocols: anyhow::Result<Vec<PortProtocol>> =
                protocols.into_iter().map(PortProtocol::try_from).collect();
            protocols
        } else {
            Ok(vec![PortProtocol::Tcp])
        }
        .with_context(|| "Failed to parse protocols")?;

        // Returns an config for each protocol
        Ok(protocols
            .into_iter()
            .map(|protocol| Self {
                source,
                destination,
                protocol,
                remote: false,
            })
            .collect())
    }
}

impl Display for PortForwardConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.remote {
            write!(
                f,
                "(remote){}:{}:{}",
                self.source, self.destination, self.protocol
            )
        } else {
            write!(f, "{}:{}:{}", self.source, self.destination, self.protocol)
        }
    }
}

/// Layer 7 protocols for ports.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum PortProtocol {
    /// TCP
    Tcp,
    /// UDP
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
    use std::str::FromStr;

    use super::*;

    /// Tests the parsing of `PortForwardConfig`.
    #[test]
    fn test_parse_port_forward_config_1() {
        assert_eq!(
            PortForwardConfig::from_notation(
                "192.168.0.1:8080:192.168.4.1:8081:TCP,UDP",
                DEFAULT_PORT_FORWARD_SOURCE
            )
            .expect("Failed to parse"),
            vec![
                PortForwardConfig {
                    source: SocketAddr::from_str("192.168.0.1:8080").unwrap(),
                    destination: SocketAddr::from_str("192.168.4.1:8081").unwrap(),
                    protocol: PortProtocol::Tcp,
                    remote: false,
                },
                PortForwardConfig {
                    source: SocketAddr::from_str("192.168.0.1:8080").unwrap(),
                    destination: SocketAddr::from_str("192.168.4.1:8081").unwrap(),
                    protocol: PortProtocol::Udp,
                    remote: false,
                }
            ]
        );
    }
    /// Tests the parsing of `PortForwardConfig`.
    #[test]
    fn test_parse_port_forward_config_2() {
        assert_eq!(
            PortForwardConfig::from_notation(
                "192.168.0.1:8080:192.168.4.1:8081:TCP",
                DEFAULT_PORT_FORWARD_SOURCE
            )
            .expect("Failed to parse"),
            vec![PortForwardConfig {
                source: SocketAddr::from_str("192.168.0.1:8080").unwrap(),
                destination: SocketAddr::from_str("192.168.4.1:8081").unwrap(),
                protocol: PortProtocol::Tcp,
                remote: false,
            }]
        );
    }
    /// Tests the parsing of `PortForwardConfig`.
    #[test]
    fn test_parse_port_forward_config_3() {
        assert_eq!(
            PortForwardConfig::from_notation(
                "0.0.0.0:8080:192.168.4.1:8081",
                DEFAULT_PORT_FORWARD_SOURCE
            )
            .expect("Failed to parse"),
            vec![PortForwardConfig {
                source: SocketAddr::from_str("0.0.0.0:8080").unwrap(),
                destination: SocketAddr::from_str("192.168.4.1:8081").unwrap(),
                protocol: PortProtocol::Tcp,
                remote: false,
            }]
        );
    }
    /// Tests the parsing of `PortForwardConfig`.
    #[test]
    fn test_parse_port_forward_config_4() {
        assert_eq!(
            PortForwardConfig::from_notation(
                "[::1]:8080:192.168.4.1:8081",
                DEFAULT_PORT_FORWARD_SOURCE
            )
            .expect("Failed to parse"),
            vec![PortForwardConfig {
                source: SocketAddr::from_str("[::1]:8080").unwrap(),
                destination: SocketAddr::from_str("192.168.4.1:8081").unwrap(),
                protocol: PortProtocol::Tcp,
                remote: false,
            }]
        );
    }
    /// Tests the parsing of `PortForwardConfig`.
    #[test]
    fn test_parse_port_forward_config_5() {
        assert_eq!(
            PortForwardConfig::from_notation("8080:192.168.4.1:8081", DEFAULT_PORT_FORWARD_SOURCE)
                .expect("Failed to parse"),
            vec![PortForwardConfig {
                source: SocketAddr::from_str("127.0.0.1:8080").unwrap(),
                destination: SocketAddr::from_str("192.168.4.1:8081").unwrap(),
                protocol: PortProtocol::Tcp,
                remote: false,
            }]
        );
    }
    /// Tests the parsing of `PortForwardConfig`.
    #[test]
    fn test_parse_port_forward_config_6() {
        assert_eq!(
            PortForwardConfig::from_notation(
                "8080:192.168.4.1:8081:TCP",
                DEFAULT_PORT_FORWARD_SOURCE
            )
            .expect("Failed to parse"),
            vec![PortForwardConfig {
                source: SocketAddr::from_str("127.0.0.1:8080").unwrap(),
                destination: SocketAddr::from_str("192.168.4.1:8081").unwrap(),
                protocol: PortProtocol::Tcp,
                remote: false,
            }]
        );
    }
    /// Tests the parsing of `PortForwardConfig`.
    #[test]
    fn test_parse_port_forward_config_7() {
        assert_eq!(
            PortForwardConfig::from_notation(
                "localhost:8080:192.168.4.1:8081",
                DEFAULT_PORT_FORWARD_SOURCE
            )
            .expect("Failed to parse"),
            vec![PortForwardConfig {
                source: "localhost:8080".to_socket_addrs().unwrap().next().unwrap(),
                destination: SocketAddr::from_str("192.168.4.1:8081").unwrap(),
                protocol: PortProtocol::Tcp,
                remote: false,
            }]
        );
    }
    /// Tests the parsing of `PortForwardConfig`.
    #[test]
    fn test_parse_port_forward_config_8() {
        assert_eq!(
            PortForwardConfig::from_notation(
                "localhost:8080:localhost:8081:TCP",
                DEFAULT_PORT_FORWARD_SOURCE
            )
            .expect("Failed to parse"),
            vec![PortForwardConfig {
                source: "localhost:8080".to_socket_addrs().unwrap().next().unwrap(),
                destination: "localhost:8081".to_socket_addrs().unwrap().next().unwrap(),
                protocol: PortProtocol::Tcp,
                remote: false,
            }]
        );
    }
}
