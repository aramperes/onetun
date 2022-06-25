#[cfg(feature = "bin")]
#[macro_use]
extern crate log;

#[cfg(feature = "bin")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use anyhow::Context;
    use onetun::{config::Config, events::Bus};

    let config = Config::from_args().with_context(|| "Failed to read config")?;
    init_logger(&config)?;

    for warning in &config.warnings {
        warn!("{}", warning);
    }

    let bus = Bus::default();
    onetun::start_tunnels(config, bus).await?;

    futures::future::pending().await
}

#[cfg(not(feature = "bin"))]
fn main() -> anyhow::Result<()> {
    Err(anyhow::anyhow!("Binary compiled without 'bin' feature"))
}

#[cfg(feature = "bin")]
fn init_logger(config: &onetun::config::Config) -> anyhow::Result<()> {
    use anyhow::Context;

    let mut builder = pretty_env_logger::formatted_timed_builder();
    builder.parse_filters(&config.log);
    builder
        .try_init()
        .with_context(|| "Failed to initialize logger")
}
