
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pcap.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <csignal>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <linux/netlink.h>
#include <thread>
#include <vector>

// our stuff
#include "message_handler.h"
#include "nl_client.h"
#include "radiotap_parse.h"
#include "socket_server.h"
#include "station.h"
#include "station_manager.h"

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTRFMT "%02x:%02x:%02x:%02x:%02x:%02x"

// to kill pcap loop on OS signal
static bool stay_alive = true;

// yoinked from linux/ether.h
// addr1 - destination addr
// addr2 - source addr
// addr3 - bssid
// addr4 - optional, just there for padding.
struct ieee80211_hdr {
    unsigned short frame_control;
    unsigned short duration_id;
    unsigned char addr1[ETH_ALEN];
    unsigned char addr2[ETH_ALEN];
    unsigned char addr3[ETH_ALEN];
    unsigned short seq_ctrl;
    unsigned short addr4[ETH_ALEN];
} __attribute__((packed));

template <typename Callback> static void print_usage_and(Callback cb)
{
    static constexpr char usage_str[] =
        "Usage: ./station-sniffer <interface_name> <packet_wait_time (ms)>";
    std::cout << usage_str << std::endl;
    cb();
}

struct packet_capture_params {
    // how often do we process a packet?
    uint packet_cadence_ms;
    // the name of the interface that we're collecting on.
    std::string device_name;
};

/**
 * @brief Dump the timestamp types (name, description) that pcap sees that the platform supports to stdout.
 * 
 * For debugging.
 * 
 * @param pd pointer to a pcap_t handle.
 */
[[maybe_unused]] static void dump_timestamp_types(pcap_t *pd)
{
    int *p_timestamp_types = nullptr;
    int n_timestamp_types  = pcap_list_tstamp_types(pd, &p_timestamp_types);
    if (n_timestamp_types == PCAP_ERROR) {
        std::cerr << "Error getting packet timestamping options: " << pcap_geterr(pd);
        return;
    }
    std::cout << n_timestamp_types << " many timestamp types supported" << std::endl;
    for (int i = 0; i < n_timestamp_types; i++) {
        std::cout << "Type # " << i << " is " << pcap_tstamp_type_val_to_name(p_timestamp_types[i])
                  << std::endl;
        std::cout << "Type # " << i << " description "
                  << pcap_tstamp_type_val_to_description(p_timestamp_types[i]) << std::endl;
    }
    pcap_free_tstamp_types(p_timestamp_types);
}

static bool is_disassoc_or_deauth_frame(ieee80211_hdr *mac_header)
{
    if (!mac_header)
        return false;
    uint8_t type    = (mac_header->frame_control & 0x0c) >> 2;
    uint8_t subtype = (mac_header->frame_control & 0xf0) >> 4;
    return (type == 0x00 && (subtype == 0x10 || subtype == 0x0a));
}

static station_manager sta_manager;
static if_info measurement_radio_info;

// typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *,
// const u_char *);
static void packet_cb(u_char *args, const struct pcap_pkthdr *pcap_hdr, const u_char *packet)
{
    constexpr static size_t radiotap_header_max_size_bytes = 2014;
    int err;
    struct ieee80211_radiotap_iterator iter;
    if (!stay_alive)
        pcap_breakloop((pcap_t *)args);

    if (pcap_hdr->len == 0) {
        std::cerr << "Packet of length zero, ignoring." << std::endl;
        return;
    }

    err = ieee80211_radiotap_iterator_init(&iter, (ieee80211_radiotap_header *)packet,
                                           radiotap_header_max_size_bytes, NULL);
    if (err) {
        printf("malformed radiotap header (init returns %d)\n", err);
        return;
    }
    const size_t eth_hdr_offset = iter._max_length;
    struct ieee80211_hdr *hdr   = (struct ieee80211_hdr *)(packet + eth_hdr_offset);

    // If we're capturing wildcard source address, or if this is a station of interest to us,
    // parse this packet's radiotap header and update the station objects.
    if (sta_manager.should_capture_all_traffic() ||
        sta_manager.station_is_whitelisted(hdr->addr2)) {
        if (is_disassoc_or_deauth_frame(hdr)) {
            printf("STA " MACSTRFMT " has disassociated from BSSID " MACSTRFMT "\n",
                   MAC2STR(hdr->addr2), MAC2STR(hdr->addr3));
            sta_manager.add_disassociated_station(hdr->addr2, hdr->addr3);
        }
        sta_manager.add_station(hdr->addr2);
        radiotap_fields rt_fields = {};
        parse_radiotap_buf(iter, (uint8_t *)packet, radiotap_header_max_size_bytes, rt_fields);

        // If we got good radiotap data, update stations.
        // Otherwise, just ignore the packet and do not touch any stations.
        if (!rt_fields.bad_fcs) {
            sta_manager.update_station_rt_fields(hdr->addr2, rt_fields);
            sta_manager.update_station_last_seen(hdr->addr2, pcap_hdr->ts.tv_sec);
            sta_manager.set_bandwidth_for_sta(hdr->addr2, measurement_radio_info.bandwidth);
        }
    }

    // Have all known stations calculate their WMA even if they have not had recent measurements,
    // because we care if there's temporally stale RSSI data.
    sta_manager.for_each_station_mutable([](station &s) { s.calculate_wma(); });
}

static int begin_packet_loop(pcap_t *pcap_handle, const packet_capture_params &pcap_params,
                             pcap_handler callback, int mode)
{
    return pcap_loop(pcap_handle, mode, callback, (u_char *)pcap_handle);
}

int main(int argc, char **argv)
{
    std::vector<std::thread> threads;
    std::cout << "Welcome to " << argv[0] << std::endl;
    if (argc < 3)
        print_usage_and([]() { exit(1); });
    const int signals_of_interest[2] = {
        SIGINT,
        SIGTERM,
    };
    const std::string capture_ifname = std::string(argv[1]);
    std::unique_ptr<nl80211_socket> netlink_sock =
        std::make_unique<nl80211_socket>(NETLINK_GENERIC);
    if (!netlink_sock->connect()) {
        std::cerr << "Could not connect netlink socket!\n";
        return 1;
    }
    std::unique_ptr<nl80211_client_impl> netlink_client =
        std::make_unique<nl80211_client_impl>(netlink_sock.get());
    if_info interface_info{};
    netlink_client->get_interface_info(capture_ifname, interface_info);

    if (!interface_info.bandwidth) {
        std::cerr << "No bandwidth information available from the interface, trying other AP "
                     "interfaces on the same phy.\n";
        netlink_client->get_wiphy_bandwidth(interface_info);

        if (!interface_info.bandwidth) {
            std::cerr << "No bandwidth information available even from another interface!\n";
        } else {
            std::cerr << "Bandwidth information is available from another interface.\n";
        }
    }

    measurement_radio_info.bandwidth = interface_info.bandwidth;
    measurement_radio_info.wiphy     = interface_info.wiphy;

    packet_capture_params pcap_params{(uint)std::stoi(argv[2], 0, 10), capture_ifname};
    char err[PCAP_ERRBUF_SIZE];
    auto pcap_handle = pcap_create(pcap_params.device_name.c_str(), err);
    if (!pcap_handle) {
        std::cerr << " Could not create a pcap handle for device '" << pcap_params.device_name
                  << "', err: " << err << std::endl;
        return 1;
    }
    pcap_set_immediate_mode(pcap_handle, 1);
    std::cout << "Got a handle to device '" << pcap_params.device_name << "'" << std::endl;
    int pcap_tstamp_type = PCAP_TSTAMP_HOST;
    int set_tstamp_err   = pcap_set_tstamp_type(pcap_handle, pcap_tstamp_type);
    if (set_tstamp_err != 0) {
        switch (set_tstamp_err) {
        case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
            std::cerr << "Could not set timestamping type '"
                      << pcap_tstamp_type_val_to_name(pcap_tstamp_type) << "' -- not supported."
                      << std::endl;
            break;
        default:
            std::cerr << "Error setting pcap timestamp type: " << pcap_geterr(pcap_handle)
                      << std::endl;
            break;
        }
    }
    if (pcap_activate(pcap_handle) != 0) {
        std::cerr << "pcap_activate error: " << pcap_geterr(pcap_handle) << std::endl;
        return 1;
    }
    for (int sig : signals_of_interest) {
        std::signal(sig, [](int signum) { stay_alive = false; });
    }

    int ret                 = 0;
    std::thread pcap_thread = std::thread([&pcap_handle, pcap_params, &ret]() {
        int loop_status = begin_packet_loop(pcap_handle, pcap_params, packet_cb, 0);
        if (loop_status != PCAP_ERROR_BREAK) {
            std::cerr << "Unexpected pcap_loop exit code: " << loop_status << std::endl;
            ret = 1;
        }
        pcap_close(pcap_handle);
        stay_alive = false;
    });
    threads.push_back(std::move(pcap_thread));
    // now, start the unix socket IPC thread.
    const std::string socket_server_path = "/tmp/uslm_socket";
    message_handler the_message_handler(sta_manager);
    std::thread unix_socket_server_thread =
        std::thread([&socket_server_path, &the_message_handler]() {
            socket_server uds_server(the_message_handler);
            uds_server.begin_serving(socket_server_path, stay_alive);
        });
    threads.push_back(std::move(unix_socket_server_thread));

    if (!measurement_radio_info.bandwidth) {
        std::thread bandwidth_thread = std::thread([&netlink_client]() {
            while (stay_alive && !measurement_radio_info.bandwidth) {
                netlink_client->get_wiphy_bandwidth(measurement_radio_info);
                if (measurement_radio_info.bandwidth) {
                    std::cerr << "Bandwidth information is now available\n";
                }
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        });
        threads.push_back(std::move(bandwidth_thread));
    }

    for (std::thread &thr : threads) {
        if (!thr.joinable()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        } else {
            thr.join();
        }
    }
    std::cout << "Done sniffing on '" << pcap_params.device_name << "', bye!" << std::endl;
    return ret;
}
