# onetun

A cross-platform, user-space WireGuard port-forwarder that requires no system network configurations.

## How it works

**onetun** opens a TCP port on your local system, from which traffic is forwarded to a TCP port on a peer in your
WireGuard network. It requires no changes to your operating system's network interfaces.

The only prerequisite is to register a peer IP and public key on your WireGuard endpoint; those are necessary for the
WireGuard endpoint to trust the onetun peer and for packets to be routed.

```
./onetun <SOURCE_ADDR> <DESTINATION_ADDR>                               \
    --endpoint-addr <public WireGuard endpoint address>                 \
    --endpoint-public-key <the public key of the peer on the endpoint>  \
    --private-key <private key assigned to onetun>                      \
    --source-peer-ip <IP assigned to onetun>                            \
    --keep-alive <optional persistent keep-alive in seconds>            \
    --log <optional log level, defaults to "info"
```

> Note: you can use environment variables for all of these flags. Use `onetun --help` for details.

### Example

Suppose your WireGuard endpoint has the following configuration, and is accessible from `140.30.3.182:51820`:

```
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
./onetun 127.0.0.1:8080 192.168.4.2:8080                                  \
    --endpoint-addr 140.30.3.182:51820                                    \
    --endpoint-public-key 'PUB_****************************************'  \
    --private-key 'PRIV_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'          \
    --source-peer-ip 192.168.4.3                                          \
    --keep-alive 10
```

You'll then see this log:

```
INFO  onetun > Tunnelling [127.0.0.1:8080]->[192.168.4.2:8080] (via [140.30.3.182:51820] as peer 192.168.4.3)
```

Which means you can now access the port locally!

```
$ curl 127.0.0.1:8080
Hello world!
```

## License

MIT. See `LICENSE` for details.
