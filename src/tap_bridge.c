/*
 * tap_bridge - Relay ethernet frames between a TAP device and two FIFOs.
 *
 * FIFOs (created by this process):
 *   /tmp/rvpn_b2d  — bridge-to-driver (TAP → Wine): bridge writes, driver reads
 *   /tmp/rvpn_d2b  — driver-to-bridge (Wine → TAP): driver writes, bridge reads
 *
 * Frame protocol on FIFOs: [uint16_t length][uint8_t frame[length]]
 * Length is native byte order (both sides are the same machine).
 *
 * The bridge opens (or attaches to) a TAP device, then:
 *   - Reads frames from TAP → writes [len][frame] to b2d FIFO
 *   - Reads [len][frame] from d2b FIFO → writes frame to TAP
 *
 * Build: gcc -Wall -O2 -o tap_bridge tap_bridge.c -lpthread
 * Usage: sudo ./tap_bridge <vpn-ip> [netmask-bits]
 *   e.g.: sudo ./tap_bridge 26.145.88.170 8
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <net/if.h>
#include <linux/if_tun.h>

/* ── Filter config (read from /tmp/rvpn_filters.json) ── */
#define FILTER_PATH    "/tmp/rvpn_filters.json"
#define MAX_FILTERS    256

typedef struct {
    int   block_ips_enabled;
    char  blocked_ips[MAX_FILTERS][48];
    int   blocked_ips_count;
    int   block_macs_enabled;
    char  blocked_macs[MAX_FILTERS][18];
    int   blocked_macs_count;
    int   block_broadcast_enabled;
    char  broadcast_block_ips[MAX_FILTERS][48];
    int   broadcast_block_ips_count;
} filter_cfg_t;

static filter_cfg_t filters;
static time_t       filters_mtime = 0;
static unsigned long drop_ip = 0, drop_mac = 0, drop_bcast = 0;

#define TAP_DEV_NAME    "radminvpn0"
#define FIFO_B2D        "/tmp/rvpn_b2d"
#define FIFO_D2B        "/tmp/rvpn_d2b"
#define MTU             1500
#define FRAME_MAX       (MTU + 14 + 4)

static volatile int running = 1;

static void sig_handler(int sig) { (void)sig; running = 0; }

static int write_exact(int fd, const void *buf, size_t n);

/* Recalculate IP header checksum for a frame (eth + IP header) */
static void fix_ip_checksum(uint8_t *frame)
{
    uint8_t ihl = (frame[14] & 0x0F) * 4;
    frame[24] = 0; frame[25] = 0;
    uint32_t sum = 0;
    for (int i = 0; i < ihl; i += 2)
        sum += ((uint32_t)frame[14 + i] << 8) | frame[15 + i];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t csum = ~((uint16_t)sum);
    frame[24] = (csum >> 8) & 0xFF;
    frame[25] = csum & 0xFF;
}

/* Write a frame to either FIFO ([len16][frame]) or TAP (raw frame) */
static int write_frame(int fd, const uint8_t *data, uint16_t len, int is_fifo)
{
    if (is_fifo) {
        if (write_exact(fd, &len, 2) < 0 ||
            write_exact(fd, data, len) < 0)
            return 0;
    } else {
        if (write(fd, data, len) != (ssize_t)len)
            return 0;
    }
    return 1;
}

/* Minecraft LAN multicast replicator:
 * Check if an ethernet frame is IPv4 with destination 224.0.2.60.
 * If so, copy the frame and replicate it as broadcast to both
 * 26.255.255.255 and 255.255.255.255, with:
 *   - dest MAC  → ff:ff:ff:ff:ff:ff (broadcast)
 *   - dest IP   → 26.255.255.255 / 255.255.255.255
 *   - recalculate IP header checksum
 *   - zero UDP checksum (valid for IPv4 UDP — checksum is optional)
 * is_fifo=1: write [len16][frame] to FIFO; is_fifo=0: write raw frame to TAP fd.
 * Returns number of replicas written (0, 1, or 2). */
static int replicate_mcast_to_bcast(int write_fd, const uint8_t *frame, uint16_t frame_len, int is_fifo)
{
    if (frame_len < 42) return 0;  /* 14 eth + 20 IP + 8 UDP minimum */

    /* Must be IPv4 */
    if (frame[12] != 0x08 || frame[13] != 0x00) return 0;

    /* Check destination IP at offset 30 (14 eth + 16 IP offset for dst) */
    if (frame[30] != 224 || frame[31] != 0 || frame[32] != 2 || frame[33] != 60)
        return 0;

    /* Must be UDP (IP protocol field at offset 23) */
    if (frame[23] != 17) return 0;

    uint8_t ihl = (frame[14] & 0x0F) * 4;
    int udp_csum_off = 14 + ihl + 6;  /* UDP checksum offset in frame */

    int count = 0;
    uint8_t copy[FRAME_MAX];
    if ((uint16_t)sizeof(copy) < frame_len) return 0;

    /* --- Replica 1: 26.255.255.255 --- */
    memcpy(copy, frame, frame_len);
    memset(copy, 0xFF, 6);           /* broadcast MAC */
    copy[30] = 26; copy[31] = 255; copy[32] = 255; copy[33] = 255;
    fix_ip_checksum(copy);
    if (frame_len > (uint16_t)(udp_csum_off + 1)) { copy[udp_csum_off] = 0; copy[udp_csum_off + 1] = 0; }
    if (write_frame(write_fd, copy, frame_len, is_fifo)) {
        count++;
        fprintf(stderr, "tap_bridge: replicated 224.0.2.60 → 26.255.255.255 (%u bytes)\n", frame_len);
    }

    /* --- Replica 2: 255.255.255.255 --- */
    memcpy(copy, frame, frame_len);
    memset(copy, 0xFF, 6);           /* broadcast MAC */
    copy[30] = 255; copy[31] = 255; copy[32] = 255; copy[33] = 255;
    fix_ip_checksum(copy);
    if (frame_len > (uint16_t)(udp_csum_off + 1)) { copy[udp_csum_off] = 0; copy[udp_csum_off + 1] = 0; }
    if (write_frame(write_fd, copy, frame_len, is_fifo)) {
        count++;
        fprintf(stderr, "tap_bridge: replicated 224.0.2.60 → 255.255.255.255 (%u bytes)\n", frame_len);
    }

    return count;
}

/* Read exactly n bytes (blocking) */
static int read_exact(int fd, void *buf, size_t n)
{
    size_t done = 0;
    while (done < n) {
        ssize_t r = read(fd, (char *)buf + done, n - done);
        if (r <= 0) return -1;
        done += r;
    }
    return 0;
}

/* Write exactly n bytes (blocking) */
static int write_exact(int fd, const void *buf, size_t n)
{
    size_t done = 0;
    while (done < n) {
        ssize_t w = write(fd, (const char *)buf + done, n - done);
        if (w <= 0) return -1;
        done += w;
    }
    return 0;
}

/* Open/attach to the TAP device */
static int open_tap(const char *dev_name)
{
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) { perror("open /dev/net/tun"); return -1; }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("ioctl TUNSETIFF");
        close(fd);
        return -1;
    }
    fprintf(stderr, "tap_bridge: attached to '%s' (fd=%d)\n", ifr.ifr_name, fd);
    return fd;
}

static void create_fifos(void)
{
    unlink(FIFO_B2D);
    unlink(FIFO_D2B);
    mkfifo(FIFO_B2D, 0666);
    mkfifo(FIFO_D2B, 0666);
    fprintf(stderr, "tap_bridge: FIFOs created: %s, %s\n", FIFO_B2D, FIFO_D2B);
}

/* ── Minimal JSON helpers (no library dependency) ── */

static const char *json_find_key(const char *json, const char *key)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return NULL;
    p += strlen(needle);
    while (*p == ' ' || *p == '\t' || *p == ':' || *p == '\n' || *p == '\r') p++;
    return p;
}

static int json_bool(const char *json, const char *key, int defval)
{
    const char *p = json_find_key(json, key);
    if (!p) return defval;
    if (strncmp(p, "true", 4) == 0) return 1;
    if (strncmp(p, "false", 5) == 0) return 0;
    return defval;
}

static int json_str_array(const char *json, const char *key,
                          char *out, int max_out, int elem_size, int max_len)
{
    const char *p = json_find_key(json, key);
    if (!p || *p != '[') return 0;
    p++; /* skip '[' */
    int count = 0;
    while (count < max_out) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',') p++;
        if (*p == ']' || *p == '\0') break;
        if (*p != '"') { p++; continue; }
        p++; /* skip opening quote */
        char *entry = out + (size_t)count * elem_size;
        int i = 0;
        while (*p && *p != '"' && i < max_len - 1) entry[i++] = *p++;
        entry[i] = '\0';
        if (*p == '"') p++;
        count++;
    }
    return count;
}

/* Load filter config from JSON file. Only reloads if file mtime changed. */
static void load_filters(void)
{
    struct stat st;
    if (stat(FILTER_PATH, &st) != 0) return;
    if (st.st_mtime == filters_mtime) return;  /* unchanged */
    filters_mtime = st.st_mtime;

    FILE *f = fopen(FILTER_PATH, "r");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 65536) { fclose(f); return; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = '\0';

    memset(&filters, 0, sizeof(filters));
    filters.block_ips_enabled       = json_bool(buf, "block_ips_enabled", 0);
    filters.block_macs_enabled      = json_bool(buf, "block_macs_enabled", 0);
    filters.block_broadcast_enabled = json_bool(buf, "block_broadcast_enabled", 0);
    filters.blocked_ips_count       = json_str_array(buf, "blocked_ips",
                                        (char *)filters.blocked_ips, MAX_FILTERS, 48, 48);
    filters.blocked_macs_count      = json_str_array(buf, "blocked_macs",
                                        (char *)filters.blocked_macs, MAX_FILTERS, 18, 18);
    filters.broadcast_block_ips_count = json_str_array(buf, "broadcast_block_ips",
                                        (char *)filters.broadcast_block_ips, MAX_FILTERS, 48, 48);
    free(buf);
    fprintf(stderr, "tap_bridge: filters loaded (ip=%d/%d mac=%d/%d bcast=%d/%d)\n",
            filters.block_ips_enabled, filters.blocked_ips_count,
            filters.block_macs_enabled, filters.blocked_macs_count,
            filters.block_broadcast_enabled, filters.broadcast_block_ips_count);
}

/* Parse "A.B.C.D" into 4 bytes. Returns 0 on success. */
static int parse_ip(const char *s, uint8_t out[4])
{
    unsigned a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return -1;
    if (a > 255 || b > 255 || c > 255 || d > 255) return -1;
    out[0] = (uint8_t)a; out[1] = (uint8_t)b;
    out[2] = (uint8_t)c; out[3] = (uint8_t)d;
    return 0;
}

/* Parse "aa:bb:cc:dd:ee:ff" into 6 bytes. Returns 0 on success. */
static int parse_mac(const char *s, uint8_t out[6])
{
    unsigned m[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
              &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) return -1;
    for (int i = 0; i < 6; i++) { if (m[i] > 255) return -1; out[i] = (uint8_t)m[i]; }
    return 0;
}

/* Check if an IPv4 address matches any entry in a filter list. */
static int ip_in_list(const uint8_t ip[4], const char list[][48], int count)
{
    for (int i = 0; i < count; i++) {
        uint8_t fip[4];
        if (parse_ip(list[i], fip) == 0 &&
            ip[0] == fip[0] && ip[1] == fip[1] && ip[2] == fip[2] && ip[3] == fip[3])
            return 1;
    }
    return 0;
}

/* Check if a MAC address matches any entry in a filter list. */
static int mac_in_list(const uint8_t mac[6], const char list[][18], int count)
{
    for (int i = 0; i < count; i++) {
        uint8_t fmac[6];
        if (parse_mac(list[i], fmac) == 0 &&
            memcmp(mac, fmac, 6) == 0)
            return 1;
    }
    return 0;
}

/* 
 * should_drop_frame — decide whether a frame should be dropped.
 * direction: 0 = TAP→driver (outgoing), 1 = driver→TAP (incoming)
 * Returns: 0 = pass, 1 = drop
 */
static int should_drop_frame(const uint8_t *frame, uint16_t len, int direction)
{
    if (len < 14) return 0;  /* too short to be ethernet */

    /* ── Block MACs (both directions) ── */
    if (filters.block_macs_enabled && filters.blocked_macs_count > 0) {
        const uint8_t *src_mac = frame;
        const uint8_t *dst_mac = frame + 6;
        if (mac_in_list(src_mac, filters.blocked_macs, filters.blocked_macs_count) ||
            mac_in_list(dst_mac, filters.blocked_macs, filters.blocked_macs_count)) {
            drop_mac++;
            if (drop_mac <= 5 || (drop_mac % 100) == 0)
                fprintf(stderr, "tap_bridge: DROP mac #%lu (dir=%s)\n", drop_mac,
                        direction ? "drv→TAP" : "TAP→drv");
            return 1;
        }
    }

    /* Must be IPv4 for IP-based checks */
    if (len < 34 || frame[12] != 0x08 || frame[13] != 0x00) return 0;

    const uint8_t *src_ip = frame + 26;
    const uint8_t *dst_ip = frame + 30;

    /* ── Block IPs (both directions) ── */
    if (filters.block_ips_enabled && filters.blocked_ips_count > 0) {
        if (ip_in_list(src_ip, filters.blocked_ips, filters.blocked_ips_count) ||
            ip_in_list(dst_ip, filters.blocked_ips, filters.blocked_ips_count)) {
            drop_ip++;
            if (drop_ip <= 5 || (drop_ip % 100) == 0)
                fprintf(stderr, "tap_bridge: DROP ip #%lu (dir=%s, src=%u.%u.%u.%u)\n",
                        drop_ip, direction ? "drv→TAP" : "TAP→drv",
                        src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
            return 1;
        }
    }

    /* ── Block Broadcast (incoming only: driver→TAP) ── */
    if (direction == 1 &&
        filters.block_broadcast_enabled && filters.broadcast_block_ips_count > 0) {
        /* Must be UDP */
        if (frame[23] != 17) return 0;

        /* Check if src or dst IP is in broadcast block list */
        if (ip_in_list(src_ip, filters.broadcast_block_ips, filters.broadcast_block_ips_count) ||
            ip_in_list(dst_ip, filters.broadcast_block_ips, filters.broadcast_block_ips_count)) {
            /* Check UDP port 4445 (src or dst) */
            uint8_t ihl = (frame[14] & 0x0F) * 4;
            if (len < (uint16_t)(14 + ihl + 8)) return 0;  /* too short for UDP hdr */
            const uint8_t *udp_hdr = frame + 14 + ihl;
            uint16_t src_port = ((uint16_t)udp_hdr[0] << 8) | udp_hdr[1];
            uint16_t dst_port = ((uint16_t)udp_hdr[2] << 8) | udp_hdr[3];
            if (src_port == 4445 || dst_port == 4445) {
                drop_bcast++;
                if (drop_bcast <= 5 || (drop_bcast % 100) == 0)
                    fprintf(stderr, "tap_bridge: DROP bcast #%lu (ip=%u.%u.%u.%u port=%u/%u)\n",
                            drop_bcast, src_ip[0], src_ip[1], src_ip[2], src_ip[3],
                            src_port, dst_port);
                return 1;
            }
        }
    }

    return 0;
}

int main(int argc, char *argv[])
{
    (void)argc; (void)argv;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    /* Attach to existing TAP (created by run.sh with ip tuntap add) */
    int tap_fd = open_tap(TAP_DEV_NAME);
    if (tap_fd < 0) return 1;

    /* Create FIFOs */
    create_fifos();

    fprintf(stderr, "tap_bridge: opening FIFOs (will block until driver connects)...\n");

    /* Open FIFOs — these block until the other side opens too.
       Open b2d (write end) first in O_RDWR to avoid blocking,
       then d2b (read end) in O_RDONLY. */
    int b2d_fd = open(FIFO_B2D, O_WRONLY);
    if (b2d_fd < 0) { perror("open b2d"); close(tap_fd); return 1; }

    int d2b_fd = open(FIFO_D2B, O_RDONLY);
    if (d2b_fd < 0) { perror("open d2b"); close(tap_fd); close(b2d_fd); return 1; }

    fprintf(stderr, "tap_bridge: FIFOs connected! Relaying frames.\n");

    /* Relay loop */
    uint8_t buf[FRAME_MAX];
    fd_set rfds;
    int maxfd = (tap_fd > d2b_fd) ? tap_fd : d2b_fd;

    unsigned long tap_to_drv = 0, drv_to_tap = 0;

    /* Initial filter load */
    load_filters();

    while (running) {
        FD_ZERO(&rfds);
        FD_SET(tap_fd, &rfds);
        FD_SET(d2b_fd, &rfds);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }
        if (ret == 0) {
            /* Poll for filter config changes every ~1s */
            load_filters();
            continue;
        }

        /* TAP → driver (b2d FIFO): read frame from TAP, write [len16][frame] */
        if (FD_ISSET(tap_fd, &rfds)) {
            ssize_t n = read(tap_fd, buf, sizeof(buf));
            if (n > 0) {
                uint16_t len = (uint16_t)n;
                if (should_drop_frame(buf, len, 0)) goto skip_tap_to_drv;
                if (write_exact(b2d_fd, &len, 2) < 0 ||
                    write_exact(b2d_fd, buf, len) < 0) {
                    fprintf(stderr, "tap_bridge: b2d write failed\n");
                    break;
                }
                tap_to_drv++;
                /* Replicate multicast 224.0.2.60 as broadcast 26.255.255.255 */
                replicate_mcast_to_bcast(b2d_fd, buf, len, 1);
                if (tap_to_drv <= 5 || (tap_to_drv % 100) == 0)
                    fprintf(stderr, "tap_bridge: TAP→drv #%lu (%d bytes)\n", tap_to_drv, (int)n);
            }
            skip_tap_to_drv: ;
        }

        /* Driver → TAP (d2b FIFO): read [len16][frame], write frame to TAP */
        if (FD_ISSET(d2b_fd, &rfds)) {
            uint16_t len;
            if (read_exact(d2b_fd, &len, 2) < 0) {
                fprintf(stderr, "tap_bridge: d2b read len failed (driver disconnected?)\n");
                break;
            }
            if (len > FRAME_MAX) {
                fprintf(stderr, "tap_bridge: bad frame len %u\n", len);
                break;
            }
            if (read_exact(d2b_fd, buf, len) < 0) {
                fprintf(stderr, "tap_bridge: d2b read frame failed\n");
                break;
            }
            if (should_drop_frame(buf, len, 1)) goto skip_drv_to_tap;
            if (write(tap_fd, buf, len) != (ssize_t)len) {
                perror("tap_bridge: write to TAP");
            }
            /* Replicate multicast 224.0.2.60 as broadcast 26.255.255.255 */
            replicate_mcast_to_bcast(tap_fd, buf, len, 0);
            drv_to_tap++;
            if (drv_to_tap <= 5 || (drv_to_tap % 100) == 0) {
                fprintf(stderr, "tap_bridge: drv→TAP #%lu (%u bytes) hex: ", drv_to_tap, len);
                for(int i=0; i < (len < 32 ? len : 32); i++) fprintf(stderr, "%02x ", buf[i]);
                fprintf(stderr, "\n");
            }
            skip_drv_to_tap: ;
        }
    }

    fprintf(stderr, "tap_bridge: shutting down (TAP→drv=%lu, drv→TAP=%lu, drops: ip=%lu mac=%lu bcast=%lu)\n",
            tap_to_drv, drv_to_tap, drop_ip, drop_mac, drop_bcast);
    close(d2b_fd);
    close(b2d_fd);
    close(tap_fd);
    unlink(FIFO_B2D);
    unlink(FIFO_D2B);
    return 0;
}
