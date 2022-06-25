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

/**
 * Creates a new bus struct
 * # Arguments
 * *none*
 * # Returns
 * A pointer to a bus struct
 */
struct Bus *onetun_new_bus(void);

/**
 * Creates a new config struct for starting a tunnel
 * # Arguments
 * * `port_forwards` - A pointer to an array of pointers to port forwards, generated with `onetun_new_port_forward`
 * * `port_forwards_len` - The length of the array of pointers to port forwards
 * * `remote_forwards` - A pointer to an array of pointers to port forwards, generated with `onetun_new_port_forward`
 * * `remote_forwards_len` - The length of the array of pointers to port forwards
 * * `private_key` - A pointer to an array of chars containing the private key
 * * `public_key` - A pointer to an array of chars containing the public key
 * * `endpoint_addr` - A pointer to an array of chars containing the endpoint address
 * * `endpoint_bind_addr` - A pointer to an array of chars containing the endpoint bind address
 * * `source_peer_ip` - A pointer to an array of chars containing the source peer IP address
 * * `keepalive_seconds` - A number representing the keepalive interval, or -1 for None
 * * `max_transmission_unit` - A number representing the maximum transmission unit
 * * `log` - A pointer to an array of chars containing the log level (e.g. "INFO", "DEBUG", "TRACE")
 * * `pcap_file` - A pointer to an array of chars containing the pcap file path, or NULL for none
 * # Returns
 * A pointer to a config struct, or NULL on failure
 * # Safety
 * All pointers must be valid and not null, unless specified and expected to be NULL.
 */
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

/**
 * Creates a new port forward configuration
 * # Arguments
 * * `source` - A list of chars representing a socket address
 * * `destination` - A list of chars representing a socket address
 * * `protocol` - Either `tcp` or `udp`
 * * `port` - Whether this forward is remote: 1 for true, 0 for false
 * # Returns
 * A pointer to a port forward config struct, or NULL on failure
 * # Safety
 * All pointers must be valid. Strings may be freed after this function returns.
 */
struct PortForwardConfig *onetun_new_port_forward(const char *source,
                                                  const char *destination,
                                                  const char *protocol,
                                                  unsigned int remote);

/**
 * Starts a new onetun tunnel
 * # Arguments
 * * `config` - The configuration for the tunnel, generated with `onetun_new_config`
 * * `bus` - The bus to publish events on, generated with `onetun_new_bus`
 * # Returns
 * 0 on success, non-zero on failure
 * # Safety
 * All pointers must be valid and not null.
 */
int32_t onetun_start_tunnels(struct Config *config, struct Bus *bus);
