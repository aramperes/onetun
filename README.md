<img align="right" alt="onetun" width="150" src=".github/onetun.png">

# onetun

A cross-platform, user-space WireGuard port-forwarder that requires **no root-access or system network configurations**.

[![crates.io](https://img.shields.io/crates/v/onetun.svg)](https://crates.io/crates/onetun)
[![MIT licensed](https://img.shields.io/crates/l/onetun.svg)](./LICENSE)
[![Build status](https://github.com/aramperes/onetun/actions/workflows/build.yml/badge.svg)](https://github.com/aramperes/onetun/actions)
[![Latest Release](https://img.shields.io/github/v/tag/aramperes/onetun?label=release)](https://github.com/aramperes/onetun/releases/latest)

## Use-case

Access TCP or UDP services running on your WireGuard network, from devices that don't have WireGuard installed.

For example,

- Personal or shared computers where you can't install WireGuard (root)
- IoT and mobile devices
- Root-less containers

## Download

onetun is available to install from [crates.io](https://crates.io/crates/onetun) with Rust ≥1.70.0:

```shell
cargo install onetun
```

You can also download the binary for Windows, macOS (Intel), and Linux (amd64) from
the [Releases](https://github.com/aramperes/onetun/releases) page.

You can also run onetun using [Docker](https://hub.docker.com/r/aramperes/onetun):

```shell
docker run --rm --name onetun --user 1000 -p 8080:8080 aramperes/onetun \
    0.0.0.0:8080:192.168.4.2:8080 [...options...]
```

You can also build onetun locally, using Rust ≥1.70.0:

```shell
git clone https://github.com/aramperes/onetun && cd onetun
cargo build --release
./target/release/onetun
```

## Usage

**onetun** opens a TCP or UDP port on your local system, from which traffic is forwarded to a port on a peer in your
WireGuard network. It requires no changes to your operating system's network interfaces: you don't need to have `root`
access, or install any WireGuard tool on your local system for it to work.

The only prerequisite is to register a peer IP and public key on the remote WireGuard endpoint; those are necessary for
the WireGuard endpoint to trust the onetun peer and for packets to be routed.

```shell
onetun [src_host:]<src_port>:<dst_host>:<dst_port>[:TCP,UDP,...] [...]    \
    --endpoint-addr <public WireGuard endpoint address>                   \
    --endpoint-public-key <the public key of the peer on the endpoint>    \
    --private-key <private key assigned to onetun>                        \
    --source-peer-ip <IP assigned to onetun>                              \
    --keep-alive <optional persistent keep-alive in seconds>              \
    --log <optional log level, defaults to "info">
```

> Note: you can use environment variables for all of these flags. Use `onetun --help` for details.

### Example

Suppose your WireGuard endpoint has the following configuration, and is accessible from `140.30.3.182:51820`:

```shell
# /etc/wireguard/wg0.conf

[Interface]
PrivateKey = ********************************************
ListenPort = 51820
Address = 192.168.4.1

# A friendly peer that hosts the TCP service we want to reach
[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AllowedIPs = 192.168.4.2/32

# Peer assigned to onetun
[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
AllowedIPs = 192.168.4.3/32
```

We want to access a web server on the friendly peer (`192.168.4.2`) on port `8080`. We can use **onetun** to open a
local port, say `127.0.0.1:8080`, that will tunnel through WireGuard to reach the peer web server:

```shell
onetun 127.0.0.1:8080:192.168.4.2:8080                                    \
    --endpoint-addr 140.30.3.182:51820                                    \
    --endpoint-public-key 'PUB_****************************************'  \
    --private-key 'PRIV_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'          \
    --source-peer-ip 192.168.4.3                                          \
    --keep-alive 10
```

You'll then see this log:

```shell
INFO  onetun > Tunneling TCP [127.0.0.1:8080]->[192.168.4.2:8080] (via [140.30.3.182:51820] as peer 192.168.4.3)
```

Which means you can now access the port locally!

```shell
curl 127.0.0.1:8080
Hello world!
```

### Multiple tunnels in parallel

**onetun** supports running multiple tunnels in parallel. For example:

```shell
onetun 127.0.0.1:8080:192.168.4.2:8080 127.0.0.1:8081:192.168.4.4:8081
INFO  onetun::tunnel > Tunneling TCP [127.0.0.1:8080]->[192.168.4.2:8080] (via [140.30.3.182:51820] as peer 192.168.4.3)
INFO  onetun::tunnel > Tunneling TCP [127.0.0.1:8081]->[192.168.4.4:8081] (via [140.30.3.182:51820] as peer 192.168.4.3)
```

... would open TCP ports 8080 and 8081 locally, which forward to their respective ports on the different peers.

#### Maximum number of tunnels

`smoltcp` imposes a compile-time limit on the number of IP addresses assigned to an interface. **onetun** increases
the default value to support most use-cases. In effect, the default limit on the number of **onetun** peers
is **7 per protocol** (TCP and UDP).

Should you need more unique IP addresses to forward ports to, you can increase the limit in `.cargo/config.toml` and recompile **onetun**.

### UDP Support

**onetun** supports UDP forwarding. You can add `:UDP` at the end of the port-forward configuration, or `UDP,TCP` to support
both protocols on the same port (note that this opens 2 separate tunnels, just on the same port)

```shell
onetun 127.0.0.1:8080:192.168.4.2:8080:UDP
INFO  onetun::tunnel > Tunneling UDP [127.0.0.1:8080]->[192.168.4.2:8080] (via [140.30.3.182:51820] as peer 192.168.4.3)

onetun 127.0.0.1:8080:192.168.4.2:8080:UDP,TCP
INFO  onetun::tunnel > Tunneling UDP [127.0.0.1:8080]->[192.168.4.2:8080] (via [140.30.3.182:51820] as peer 192.168.4.3)
INFO  onetun::tunnel > Tunneling TCP [127.0.0.1:8080]->[192.168.4.2:8080] (via [140.30.3.182:51820] as peer 192.168.4.3)
```

Note: UDP support is totally experimental. You should read the UDP portion of the **Architecture** section before using
it in any production capacity.

### IPv6 Support

**onetun** supports both IPv4 and IPv6. In fact, you can use onetun to forward some IP version to another, e.g. 6-to-4:

```shell
onetun [::1]:8080:192.168.4.2:8080
INFO  onetun::tunnel > Tunneling TCP [[::1]:8080]->[192.168.4.2:8080] (via [140.30.3.182:51820] as peer 192.168.4.3)
```

Note that each tunnel can only support one "source" IP version and one "destination" IP version. If you want to support
both IPv4 and IPv6 on the same port, you should create a second port-forward:

```shell
onetun [::1]:8080:192.168.4.2:8080 127.0.0.1:8080:192.168.4.2:8080
INFO  onetun::tunnel > Tunneling TCP [[::1]:8080]->[192.168.4.2:8080] (via [140.30.3.182:51820] as peer 192.168.4.3)
INFO  onetun::tunnel > Tunneling TCP [127.0.0.1:8080]->[192.168.4.2:8080] (via [140.30.3.182:51820] as peer 192.168.4.3)
```

### Packet Capture

For debugging purposes, you can enable the capture of IP packets sent between onetun and the WireGuard peer.
The output is a libpcap capture file that can be viewed with Wireshark.

```shell
onetun --pcap wg.pcap 127.0.0.1:8080:192.168.4.2:8080
INFO  onetun::pcap > Capturing WireGuard IP packets to wg.pcap
INFO  onetun::tunnel > Tunneling TCP [127.0.0.1:8080]->[192.168.4.2:8080] (via [140.30.3.182:51820] as peer 192.168.4.3)
```

To capture packets sent to and from the onetun local port, you must use an external tool like `tcpdump` with root access:

```shell
sudo tcpdump -i lo -w local.pcap 'dst 127.0.0.1 && port 8080'
```

### WireGuard Options

By default, onetun will create the UDP socket to communicate with the WireGuard endpoint on all interfaces and on a dynamic port,
i.e. `0.0.0.0:0` for IPv4 endpoints, or `[::]:0` for IPv6.
You can bind to a static address instead using `--endpoint-bind-addr`:

```shell
onetun --endpoint-bind-addr 0.0.0.0:51820 --endpoint-addr 140.30.3.182:51820 [...]
```

The security of the WireGuard connection can be further enhanced with a **pre-shared key** (PSK). You can generate such a key with the `wg genpsk` command, and provide it using `--preshared-key`.
The peer must also have this key configured using the `PresharedKey` option.

```shell
onetun --preshared-key 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' [...]
```

## Architecture

**In short:** onetun uses [smoltcp's](https://github.com/smoltcp-rs/smoltcp) TCP/IP and UDP stack to generate IP packets
using its state machine ("virtual interface"). The generated IP packets are
encrypted by [boringtun](https://github.com/cloudflare/boringtun) and sent to the WireGuard endpoint. Encrypted IP packets received
from the WireGuard endpoint are decrypted using boringtun and sent through the smoltcp virtual interface state machine.
onetun creates "virtual sockets" in the virtual interface to forward data sent from inbound connections,
as well as to receive data from the virtual interface to forward back to the local client.

---

onetun uses [tokio](https://github.com/tokio-rs/tokio), the async runtime, to listen for new TCP connections on the
given port.

When a client connects to the onetun's TCP port, a "virtual client" is
created in a [smoltcp](https://github.com/smoltcp-rs/smoltcp) "virtual" TCP/IP interface, which runs fully inside the onetun
process. An ephemeral "virtual port" is assigned to the "virtual client", which maps back to the local client.

When the real client opens the connection, the virtual client socket opens a TCP connection to the virtual server
(a dummy socket bound to the remote host/port). The virtual interface in turn crafts the `SYN` segment and wraps it in an IP packet.
Because of how the virtual client and server are configured, the IP packet is crafted with a source address
being the configured `source-peer-ip` (`192.168.4.3` in the example above),
and the destination address matches the port-forward's configured destination (`192.168.4.2`).

By doing this, we let smoltcp handle the crafting of the IP packets, and the handling of the client's TCP states.
Instead of actually sending those packets to the virtual server,
we can intercept them in the virtual interface and encrypt the packets using [boringtun](https://github.com/cloudflare/boringtun),
and send them to the WireGuard endpoint's UDP port.

Once the WireGuard endpoint receives an encrypted IP packet, it decrypts it using its private key and reads the IP packet.
It reads the destination address, re-encrypts the IP packet using the matching peer's public key, and sends it off to
the peer's UDP endpoint.

The peer receives the encrypted IP and decrypts it. It can then read the inner payload (the TCP segment),
forward it to the server's port, which handles the TCP segment. The TCP server responds with `SYN-ACK`, which goes back through
the peer's local WireGuard interface, gets encrypted, forwarded to the WireGuard endpoint, and then finally back to onetun's UDP port.

When onetun receives an encrypted packet from the WireGuard endpoint, it decrypts it using boringtun.
The resulting IP packet is dispatched to the corresponding virtual interface running inside onetun;
the IP packet is then read and processed by the virtual interface, and the virtual client's TCP state is updated.

Whenever data is sent by the real client, it is simply "sent" by the virtual client, which kicks off the whole IP encapsulation
and WireGuard encryption again. When data is sent by the real server, it ends up routed in the virtual interface, which allows
the virtual client to read it. When the virtual client reads data, it simply pushes the data back to the real client.

This work is all made possible by [smoltcp](https://github.com/smoltcp-rs/smoltcp) and [boringtun](https://github.com/cloudflare/boringtun),
so special thanks to the developers of those libraries.

### UDP

UDP support is experimental. Since UDP messages are stateless, there is no perfect way for onetun to know when to release the
assigned virtual port back to the pool for a new peer to use. This would cause issues over time as running out of virtual ports
would mean new datagrams get dropped. To alleviate this, onetun will cap the amount of ports used by one peer IP address;
if another datagram comes in from a different port but with the same IP, the least recently used virtual port will be freed and assigned
to the new peer port. At that point, any datagram packets destined for the reused virtual port will be routed to the new peer,
and any datagrams received by the old peer will be dropped.

In addition, in cases where many IPs are exhausting the UDP virtual port pool in tandem, and a totally new peer IP sends data,
onetun will have to pick the least recently used virtual port from _any_ peer IP and reuse it. However, this is only allowed
if the least recently used port hasn't been used for a certain amount of time. If all virtual ports are truly "active"
(with at least one transmission within that time limit), the new datagram gets dropped due to exhaustion.

All in all, I would not recommend using UDP forwarding for public services, since it's most likely prone to simple DoS or DDoS.

## HTTP/SOCKS Proxy

**onetun** is a Transport-layer proxy (also known as port forwarding); it is not in scope to provide
a HTTP/SOCKS proxy server. However, you can easily chain **onetun** with a proxy server on a remote
that is locked down to your WireGuard network.

For example, you could run [dante-server](https://www.inet.no/dante/) on a peer (ex. `192.168.4.2`) with the following configuration:

```
# /etc/danted.conf

logoutput: syslog
user.privileged: root
user.unprivileged: nobody

internal: 192.168.4.2 port=1080
external: eth0

socksmethod: none
clientmethod: none

# Locks down proxy use to WireGuard peers (192.168.4.x)
client pass {
    from: 192.168.4.0/24 to: 0.0.0.0/0
}
socks pass {
    from: 192.168.4.0/24 to: 0.0.0.0/0
}
```

Then use **onetun** to expose the SOCKS5 proxy locally:

```shell
onetun 127.0.0.1:1080:192.168.4.2:1080
INFO  onetun::tunnel > Tunneling TCP [127.0.0.1:1080]->[192.168.4.2:1080] (via [140.30.3.182:51820] as peer 192.168.4.3)
```

Test with `curl` (or configure your browser):

```shell
curl -x socks5://127.0.0.1:1080 https://ifconfig.me
```

## Contributing and Maintenance

I will gladly accept contributions to onetun, and set aside time to review all pull-requests.
Please consider opening a GitHub issue if you are unsure if your contribution is within the scope of the project.

**Disclaimer**: I do not have enough personal time to actively maintain onetun besides open-source contributions.

## License

MIT License. See `LICENSE` for details. Copyright &copy; 2023 Aram Peres.
