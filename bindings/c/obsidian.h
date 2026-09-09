#ifndef OBSIDIAN_H
#define OBSIDIAN_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Callback types
typedef int (*socket_protect_fn)(int fd);
typedef void (*status_cb_fn)(const char* status, const char* detail);
typedef void (*stats_cb_fn)(int64_t bytes_sent, int64_t bytes_recv, int64_t tx_speed, int64_t rx_speed);

/**
 * Start an Obsidian VPN tunnel using an operating system provided TUN file descriptor.
 * Primary entry point for Android VpnService.
 *
 * @param uri           Obsidian connection URI (e.g. "obsidian://...", "vpn://...", "OBSDN-...")
 * @param tun_fd        File descriptor of the TUN interface (e.g. from VpnService.Builder.establish().getFd())
 * @param mtu           Interface MTU (e.g. 1420)
 * @param protect_fn    Callback invoked before sockets connect (VpnService.protect). Return 1 on success, 0 on failure.
 * @param status_fn     Callback invoked on tunnel state transitions. Can be NULL.
 * @param stats_fn      Callback invoked periodically with throughput metrics. Can be NULL.
 * @return              Dynamically allocated session ID string (free with ObsidianFreeString), or NULL on failure.
 */
char* ObsidianStartTunnelWithFd(
    const char* uri,
    int tun_fd,
    int mtu,
    socket_protect_fn protect_fn,
    status_cb_fn status_fn,
    stats_cb_fn stats_fn
);

/**
 * Start an Obsidian VPN tunnel using in-memory packet exchange.
 * Primary entry point for iOS NetworkExtension NEPacketTunnelProvider packetFlow.
 */
char* ObsidianStartPacketTunnel(
    const char* uri,
    int mtu,
    socket_protect_fn protect_fn,
    status_cb_fn status_fn,
    stats_cb_fn stats_fn
);

/**
 * Inject an incoming IP packet (from host OS / iOS packetFlow) into the tunnel.
 * @return 0 on success, -1 on failure.
 */
int ObsidianInjectPacket(const char* session_id, const char* data, int length);

/**
 * Stop an active tunnel session.
 * @return 0 on success, -1 on failure.
 */
int ObsidianStopTunnel(const char* session_id);

/**
 * Start a local SOCKS5 proxy server.
 * @param listen_addr e.g. "127.0.0.1:10808"
 * @return 0 on success, -1 on failure.
 */
int ObsidianStartLocalProxy(const char* listen_addr);

/**
 * Stop the local SOCKS5 proxy server.
 * @return 0 on success, -1 on failure.
 */
int ObsidianStopLocalProxy(void);

/**
 * Parse an Obsidian URI and return JSON configuration string.
 * @return Dynamically allocated JSON string (free with ObsidianFreeString), or NULL on failure.
 */
char* ObsidianParseURI(const char* uri);

/**
 * Free a string allocated by Obsidian C-ABI functions.
 */
void ObsidianFreeString(char* str);

#ifdef __cplusplus
}
#endif

#endif // OBSIDIAN_H
