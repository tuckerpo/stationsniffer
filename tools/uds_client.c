#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>

struct sta_lm {
    int32_t error_code;
    int8_t rssi;
    int16_t channel_number;
    uint8_t bandwidth;
    uint64_t timestamp;
} __attribute__((packed));

struct sta_dissasoc_msg {
    uint8_t disassociated;
    uint8_t bssid[6];
};

enum message_type {
    MSG_REGISTER_STA = 0x01,

    MSG_UNREGISTER_STA = 0x02,

    MSG_GET_STA_STATS = 0x04,

    MSG_GET_STA_WMI_STATS = 0x08,

    MSG_CHANGE_KEEPALIVE_TIMEOUT_MS = 0x10,

    MSG_CHANGE_PACKET_PERIODICITY_MS = 0x20,
};

enum error_type {
    ERROR_OK = 0x00,

    ERROR_STA_NOT_KNOWN = 0x01,

    ERROR_BAD_MESSAGE = 0x02,
};

static char *err_type_2_str(enum error_type et)
{
    switch (et) {
    case ERROR_OK:
        return "ERROR_OK";
    case ERROR_STA_NOT_KNOWN:
        return "ERROR_STA_NOT_KNOWN";
    case ERROR_BAD_MESSAGE:
        return "ERROR_BAD_MESSAGE";
    }
    return "Unknown error type!";
}

static void print_usage() { fprintf(stderr, "Usage: ./uds_client <socket_path> <sta_mac>\n"); }

static int validate_mac(uint8_t *buf, size_t len)
{
    size_t i;
    size_t hex_count         = 0;
    size_t current_hex_count = 0;
    for (i = 0; i < len; i++) {
        if (isxdigit(buf[i])) {
            ++hex_count;
            ++current_hex_count;
        } else {
            // did we see the correct number of hex digits prior to seeing ':'?
            if (current_hex_count % 2 != 0) {
                return -1;
            } else {
                current_hex_count = 0;
            }
            // is the seperator char ':'?
            if (buf[i] != ':') {
                return -1;
            }
        }
    }
    // did we see a total of 12 bytes?
    if (hex_count != 12)
        return -1;
    return 0;
}

/**
 * @brief Place a MAC address inside of a binary buffer.
 *
 * @param buf The buffer to place the MAC address into.
 * @param buflen The size of the buffer.
 * @param macbuf The MAC address, assumed to be 6 bytes.
 * @param offset The offset into buf to begin placing the MAC addr at.
 *
 * Note: null terminates 'buf' at offset + 6 + 1
 */
static void fill_mac(unsigned char *buf, size_t buflen, unsigned char *macbuf, size_t offset)
{
    int i;
    for (i = 0; i < 6; i++) {
        if (offset + i < buflen) {
            buf[offset + i] = macbuf[i];
        }
    }
    buf[offset + i + 1] = '\0';
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        print_usage();
        return 1;
    }
    printf("%s\n", argv[0]);
    int fd;
    struct sockaddr_un addr;
    fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    char *path    = argv[1];
    char *sta_mac = argv[2];
    if (validate_mac((uint8_t *)sta_mac, strlen(sta_mac)) == -1) {
        fprintf(stderr, "STA MAC %s seems malformed. Expected format: aa:bb:cc:dd:ee:ff\n",
                sta_mac);
        return 1;
    }
    unsigned char mac[6];
    sscanf(sta_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4],
           &mac[5]);
    printf("Attemping to connect to %s\n", path);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, strlen(path));
    int len = strlen(addr.sun_path) + sizeof(addr.sun_family);
    if (connect(fd, (struct sockaddr *)&addr, len) < 0) {
        perror("connect");
        return 1;
    }

    int i;
    unsigned char buf[256];
    /* Offset at which a STA MAC is expected, for all messages, in # of bytes */
    size_t sta_mac_offset = 4;
    buf[0] = MSG_REGISTER_STA;
    // padding, since message_type is int32
    buf[1] = 0x00;
    buf[2] = 0x00;
    buf[3] = 0x00;
    fill_mac(buf, sizeof(buf), mac, sta_mac_offset);

    if (send(fd, buf, 11, 0) < 0) {
        perror("send");
        return 1;
    }

    unsigned char rxbuf[256];
    if (recv(fd, rxbuf, sizeof(rxbuf), 0) < 0) {
        perror("recv");
        return 1;
    }

    enum error_type err = *(enum error_type *)rxbuf;
    printf("Request to register station error code %s\n", err_type_2_str(err));

    // ask for station stats periodically
    while (1) {
        buf[0] = MSG_GET_STA_STATS;
        // padding, since message_type is int32
        buf[1] = 0x00;
        buf[2] = 0x00;
        buf[3] = 0x00;
        // done padding.
        fill_mac(buf, sizeof(buf), mac, sta_mac_offset);
        if (send(fd, buf, 11, 0) < 0) {
            perror("send");
            return 1;
        }
        sleep(5);
        if (recv(fd, rxbuf, sizeof(rxbuf), 0) < 0) {
            perror("recv");
            return 1;
        }
        struct sta_lm *link_metrics_response = (struct sta_lm *)rxbuf;
        if (link_metrics_response->error_code != ERROR_OK) {
            printf("Error code! %d (%s)\n", link_metrics_response->error_code,
                   err_type_2_str(link_metrics_response->error_code));
        } else {
            printf("STA MAC %s channel number %d bw %u rssi %d timestamp %" PRIu64 "\n", sta_mac,
                   link_metrics_response->channel_number, link_metrics_response->bandwidth,
                   link_metrics_response->rssi, link_metrics_response->timestamp);
        }
        // ask for disassociated stations periodically
        buf[0] = 0x40;
        // padding, since message_type is int32
        buf[1] = 0x00;
        buf[2] = 0x00;
        buf[3] = 0x00;
        // done padding.
        fill_mac(buf, sizeof(buf), mac, sta_mac_offset);
        if (send(fd, buf, 11, 0) < 0) {
            perror("send");
            return 1;
        }
        sleep(1);
        if (recv(fd, rxbuf, sizeof(rxbuf), 0) < 0) {
            perror("recv");
            return 1;
        }
        struct sta_dissasoc_msg *disassoc_msg = (struct sta_dissasoc_msg *)rxbuf;
        printf("has STA %s disconnected? %d\n", sta_mac, disassoc_msg->disassociated);
    }
}