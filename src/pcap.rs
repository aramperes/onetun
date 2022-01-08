use crate::events::Event;
use crate::Bus;
use anyhow::Context;
use smoltcp::time::Instant;
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};

struct Pcap {
    writer: BufWriter<File>,
}

/// libpcap file writer
/// This is mostly taken from `smoltcp`, but rewritten to be async.
impl Pcap {
    async fn flush(&mut self) -> anyhow::Result<()> {
        self.writer
            .flush()
            .await
            .with_context(|| "Failed to flush pcap writer")
    }

    async fn write(&mut self, data: &[u8]) -> anyhow::Result<usize> {
        self.writer
            .write(data)
            .await
            .with_context(|| format!("Failed to write {} bytes to pcap writer", data.len()))
    }

    async fn write_u16(&mut self, value: u16) -> anyhow::Result<()> {
        self.writer
            .write_u16(value)
            .await
            .with_context(|| "Failed to write u16 to pcap writer")
    }

    async fn write_u32(&mut self, value: u32) -> anyhow::Result<()> {
        self.writer
            .write_u32(value)
            .await
            .with_context(|| "Failed to write u32 to pcap writer")
    }

    async fn global_header(&mut self) -> anyhow::Result<()> {
        self.write_u32(0xa1b2c3d4).await?; // magic number
        self.write_u16(2).await?; // major version
        self.write_u16(4).await?; // minor version
        self.write_u32(0).await?; // timezone (= UTC)
        self.write_u32(0).await?; // accuracy (not used)
        self.write_u32(65535).await?; // maximum packet length
        self.write_u32(101).await?; // link-layer header type (101 = IP)
        self.flush().await
    }

    async fn packet_header(&mut self, timestamp: Instant, length: usize) -> anyhow::Result<()> {
        assert!(length <= 65535);

        self.write_u32(timestamp.secs() as u32).await?; // timestamp seconds
        self.write_u32(timestamp.micros() as u32).await?; // timestamp microseconds
        self.write_u32(length as u32).await?; // captured length
        self.write_u32(length as u32).await?; // original length
        Ok(())
    }

    async fn packet(&mut self, timestamp: Instant, packet: &[u8]) -> anyhow::Result<()> {
        self.packet_header(timestamp, packet.len())
            .await
            .with_context(|| "Failed to write packet header to pcap writer")?;
        self.write(packet)
            .await
            .with_context(|| "Failed to write packet to pcap writer")?;
        self.writer
            .flush()
            .await
            .with_context(|| "Failed to flush pcap writer")?;
        self.flush().await
    }
}

/// Listens on the event bus for IP packets sent from and to the WireGuard tunnel.
pub async fn capture(pcap_file: String, bus: Bus) -> anyhow::Result<()> {
    let mut endpoint = bus.new_endpoint();
    let file = File::create(&pcap_file)
        .await
        .with_context(|| "Failed to create pcap file")?;
    let writer = BufWriter::new(file);

    let mut writer = Pcap { writer };
    writer
        .global_header()
        .await
        .with_context(|| "Failed to write global header to pcap writer")?;

    info!("Capturing WireGuard IP packets to {}", &pcap_file);
    loop {
        match endpoint.recv().await {
            Event::InboundInternetPacket(_proto, ip) => {
                let instant = Instant::now();
                writer
                    .packet(instant, &ip)
                    .await
                    .with_context(|| "Failed to write inbound IP packet to pcap writer")?;
            }
            Event::OutboundInternetPacket(ip) => {
                let instant = Instant::now();
                writer
                    .packet(instant, &ip)
                    .await
                    .with_context(|| "Failed to write output IP packet to pcap writer")?;
            }
            _ => {}
        }
    }
}
