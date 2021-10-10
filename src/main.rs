#[macro_use]
extern crate log;

use std::net::UdpSocket;
use std::sync::Arc;

use anyhow::Context;
use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use boringtun::device::peer::Peer;
use boringtun::noise::Tunn;
use clap::{App, Arg};

use crate::config::Config;

mod config;

fn main() -> anyhow::Result<()> {
    pretty_env_logger::init_custom_env("ONETUN_LOG");
    let config = Config::from_args().with_context(|| "Failed to read config")?;
    debug!("Parsed arguments: {:?}", config);

    // TODO
    // 1. Listen on source addr (sA) -> encapsulate packets with peer IP -> send to endpoint IP (sB)
    // 2. Connect to endpoint IP (sB) -> decapsulate packets -> send to source addr (sA)

    Ok(())
}
