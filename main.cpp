
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <csignal>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string_view>
#include <vector>

// our stuff
#include "radiotap_parse.h"
#include "station.h"

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

void printMacToStream(std::ostream &os, unsigned char MACData[])
{
    char oldFill = os.fill('0');

    os << std::setw(2) << std::hex << static_cast<unsigned int>(MACData[0]);
    for (uint i = 1; i < 6; ++i) {
        os << ':' << std::setw(2) << std::hex << static_cast<unsigned int>(MACData[i]);
    }

    os.fill(oldFill);
}

template <typename Callback> static void print_usage_and(Callback cb)
{
    static constexpr std::string_view usage_str = "Usage: ./pcap <device> <packet_wait_time (mS)>";
    std::cout << usage_str << std::endl;
    cb();
}

static const std::chrono::milliseconds STATION_KEEPALIVE_TIMEOUT = std::chrono::milliseconds(5000);

struct packet_capture_params {
    // how often do we process a packet?
    uint packet_cadence_ms;
    // the name of the interface that we're collecting on.
    std::string device_name;
};

// list of macs that we want to measure for.
static std::vector<uint8_t *> whitelisted_macs;

static std::vector<station> stations;

[[maybe_unused]] static void stop_collecting_metrics(uint8_t mac[ETH_ALEN])
{
    bool found = std::find_if(stations.begin(), stations.end(), [&mac](const station &s) {
                     return std::memcmp(mac, s.get_mac().data(), ETH_ALEN);
                 }) != stations.end();

    // this is not an error case -- we should return true here.
    if (!found) {
        std::cout << "Station " << std::hex << mac
                  << " not found, ignoring request to stop collecting metrics." << std::endl;
        return;
    }

    std::remove_if(whitelisted_macs.begin(), whitelisted_macs.end(),
                   [&mac](const uint8_t *whitelisted_mac) {
                       return std::memcmp(whitelisted_mac, mac, ETH_ALEN) == 0;
                   });

    std::remove_if(stations.begin(), stations.end(), [&mac](const station &s) {
        return std::memcmp(s.get_mac().data(), mac, ETH_ALEN) == 0;
    });
}

static void register_station_of_interest(uint8_t mac[ETH_ALEN])
{
    for (const station &s : stations) {
        if (std::memcmp(mac, s.get_mac().data(), ETH_ALEN) == 0) {
            std::cout << " Station " << std::hex << mac
                      << " already known, ignoring register request";
        }
    }
    whitelisted_macs.push_back(mac);
}

/**
 * @brief Call 'cb' on every station in the station list (immutable).
 * 
 * @tparam Callback 
 * @param cb the callback to call with a station passed in.
 */
template <typename Callback> void station_for_each(Callback cb)
{
    for (const station &sta : stations)
        cb(sta);
}

/**
 * @brief Call 'cb' on every station in the station list (mutable).
 * 
 * @tparam Callback 
 * @param cb the callback to call with a station passed in. 
 */
template <typename Callback> void station_for_each_mutable(Callback cb)
{
    for (station &s : stations)
        cb(s);
}

/**
 * @brief Walks every station and checks if they've been seen in at least timeout_ms milliseconds.
 * 
 * If not, they are removed from station_list
 * 
 * @param station_list the list of stations to walk
 */
static void station_keepalive_check(std::vector<station> &station_list,
                                    std::chrono::milliseconds timeout_ms)
{
    stations.erase(std::remove_if(stations.begin(), stations.end(),
                                  [&timeout_ms](const station &s) {
                                      bool timed_out = s.is_timed_out_ms(timeout_ms);
                                      if (timed_out) {
                                          printf("Station " MACSTRFMT
                                                 " has timed out. Removing it.\n",
                                                 MAC2STR(s.get_mac().data()));
                                      }
                                      return timed_out;
                                  }),
                   stations.end());
}

// typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *,
// const u_char *);
static void packet_cb(u_char *args, const struct pcap_pkthdr *pcap_hdr, const u_char *packet)
{
    int err;
    struct ieee80211_radiotap_iterator iter;
    if (!stay_alive)
        pcap_breakloop((pcap_t *)args);

    err = ieee80211_radiotap_iterator_init(&iter, (ieee80211_radiotap_header *)packet, 2014, NULL);
    if (err) {
        printf("malformed radiotap header (init returns %d)\n", err);
        return;
    }
    const size_t eth_hdr_offset = iter._max_length;
    struct ieee80211_hdr *hdr   = (struct ieee80211_hdr *)(packet + eth_hdr_offset);
    auto it =
        std::find_if(whitelisted_macs.begin(), whitelisted_macs.end(), [&hdr](const uint8_t *mac) {
            return std::memcmp(hdr->addr2, mac, ETH_ALEN) == 0;
        });
    if (it != whitelisted_macs.end()) {

        // check if it's already accounted for.
        auto station_it = std::find_if(stations.begin(), stations.end(), [&hdr](const station &s) {
            return std::memcmp(hdr->addr2, s.get_mac().data(), ETH_ALEN) == 0;
        });
        // if it's not already being tracked, and we care about it, add it to the station list.
        if (station_it == stations.end()) {
            stations.push_back(hdr->addr2);
        }

    } else {
        // no work to be done, it's not a packet from a station we care about. bail.
        return;
    }

    radiotap_fields rt_fields;
    parse_radiotap_buf(iter, (uint8_t *)packet, 2014, rt_fields);

    if (rt_fields.bad_fcs) {
        std::cout << "Malformed radiotap header." << std::endl;
        return;
    }

    auto sta_it = std::find_if(stations.begin(), stations.end(), [&hdr](const station &s) {
        return std::memcmp(s.get_mac().data(), hdr->addr2, ETH_ALEN) == 0;
    });
    // this shouldnt happen, but hey.
    if (sta_it == stations.end())
        return;
    sta_it->update_rt_fields(rt_fields);

    // do some housekeeping
    station_keepalive_check(stations, STATION_KEEPALIVE_TIMEOUT);

    station_for_each_mutable([](station &s) { s.calculate_wma(); });

    station_for_each([](const station &s) {
        std::cout << "Station ";
        printMacToStream(std::cout, s.get_mac().data());
        std::cout << std::dec << std::endl
                  << " RSSI " << (int)s.get_rssi() << " WMA RSSI " << (int)s.get_wma_rssi()
                  << " Channel " << s.get_channel() << " (" << s.get_frequency() << " mHz)"
                  << std::endl;
    });

    return;
}

static int begin_packet_loop(pcap_t *pcap_handle, const packet_capture_params &pcap_params,
                             pcap_handler callback, int mode)
{
    return pcap_loop(pcap_handle, mode, callback, (u_char *)pcap_handle);
}

int main(int argc, char **argv)
{
    std::cout << "Welcome to " << argv[0] << std::endl;
    if (argc < 3)
        print_usage_and([]() { exit(1); });
    const int signals_of_interest[2] = {
        SIGINT,
        SIGTERM,
    };
    packet_capture_params pcap_params{(uint)std::stoi(argv[2], 0, 10), argv[1]};
    char err[PCAP_ERRBUF_SIZE];
    auto pcap_handle = pcap_open_live(pcap_params.device_name.c_str(), BUFSIZ, 1,
                                      pcap_params.packet_cadence_ms, err);
    if (!pcap_handle) {
        std::cout << "Could not get a pcap handle on device '" << pcap_params.device_name
                  << "', pcap error: " << err << std::endl;
        return 1;
    }
    std::cout << "Got a handle to device '" << pcap_params.device_name << "'" << std::endl;

    for (int sig : signals_of_interest) {
        std::signal(sig, [](int signum) { stay_alive = false; });
    }
    // DEBUG
    uint8_t station_of_interest[ETH_ALEN] = {0x88, 0xf0, 0x31, 0x79, 0xdc, 0x52};
    register_station_of_interest(station_of_interest);
    int loop_status = begin_packet_loop(pcap_handle, pcap_params, packet_cb, 0);
    if (loop_status != PCAP_ERROR_BREAK) {
        std::cout << "Unexpected pcap_loop exit code: " << loop_status << std::endl;
    }
    pcap_close(pcap_handle);
    std::cout << "Done sniffing on '" << pcap_params.device_name << "', bye!" << std::endl;
    return 0;
}