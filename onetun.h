#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


/**
 * The capacity of the channel for received IP packets.
 */
#define DISPATCH_CAPACITY 1000

typedef struct Bus Bus;

typedef struct Config Config;

typedef struct PortForwardConfig PortForwardConfig;

struct Bus *onetun_new_bus(void);

struct Config *onetun_new_config(struct PortForwardConfig *const *port_forwards,
                                 unsigned int port_forwards_len,
                                 struct PortForwardConfig *const *remote_forwards,
                                 unsigned int remote_forwards_len,
                                 const char *private_key,
                                 const char *public_key,
                                 const char *endpoint_addr,
                                 const char *endpoint_bind_addr,
                                 const char *source_peer_ip,
                                 int keepalive_seconds,
                                 int max_transmission_unit,
                                 const char *log,
                                 const char *pcap_file);

struct PortForwardConfig *onetun_new_port_forward(const char *source,
                                                  const char *destination,
                                                  const char *protocol,
                                                  unsigned int remote);

int32_t onetun_start_tunnels(struct Config *config, struct Bus *bus);
