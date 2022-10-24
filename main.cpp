
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
#include <cstring>
#include <iostream>
#include <string_view>
#include <vector>

// rt stuff
#include "radiotap-library/platform.h"
#include "radiotap-library/radiotap.h"
#include "radiotap-library/radiotap_iter.h"

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTRFMT "%02x:%02x:%02x:%02x:%02x:%02x"

constexpr size_t ETH_ALEN = 6;

// yoinked from linux/ether.h
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
    static constexpr std::string_view usage_str = "Usage: ./pcap <device> <packet_wait_time (mS)>";
    std::cout << usage_str << std::endl;
    cb();
}

static const std::chrono::milliseconds STATION_KEEPALIVE_TIMEOUT = std::chrono::milliseconds(5000);

struct radiotap_fields {
    int8_t rssi; // dBm
    uint16_t channel_number;
    uint16_t channel_frequency; // mHz
    bool bad_fcs;               // bad frame control sequence, indicates that this is bogus crap.
};

struct rssi_measurement {
    int8_t m_rssi_value;
    uint16_t m_measurement_channel;
    std::chrono::time_point<std::chrono::high_resolution_clock> m_measurement_timestamp;
};

class station {
    radiotap_fields m_rt_fields;
    std::array<uint8_t, ETH_ALEN> m_mac;
    uint32_t m_rssi_wma;
    // the end of this vector will contain the most recent instantaneous measurement.
    std::vector<rssi_measurement> m_rssi_measurements;

public:
    station(uint8_t mac[ETH_ALEN])
    {
        for (int i = 0; i < ETH_ALEN; i++)
            m_mac[i] = mac[i];
    }
    station(const std::array<uint8_t, ETH_ALEN> &mac) { m_mac = mac; }
    virtual ~station() = default;
    std::array<uint8_t, ETH_ALEN> get_mac() const { return m_mac; }
    int8_t get_rssi() const { return m_rt_fields.rssi; }
    // second nibble of MSB of MAC being 2, E, A or 6 seems to indicate mac randomization (which is canonically only implemented by mobile stations)
    bool is_potentially_mobile() const
    {
        return ((get_mac()[0] & 0x0f) == 0x0A) || ((get_mac()[0] & 0x0f) == 0x0E) ||
               ((get_mac()[0] & 0x0f) == 0x06) || ((get_mac()[0] & 0x0f) == 0x02);
    }
    void update_rt_fields(const radiotap_fields &rt_f)
    {
        m_rt_fields = rt_f;
        m_rssi_measurements.push_back(
            {m_rt_fields.rssi, m_rt_fields.channel_number, std::chrono::system_clock::now()});
    }
    int16_t get_frequency() const { return m_rt_fields.channel_frequency; }
    uint16_t get_channel() const { return m_rt_fields.channel_number; }
    std::chrono::time_point<std::chrono::high_resolution_clock> get_last_rssi_meas_time() const
    {
        return m_rssi_measurements.back().m_measurement_timestamp;
    }
    bool is_timed_out_ms(std::chrono::milliseconds timeout_ms) const
    {
        auto now                                          = std::chrono::system_clock::now();
        std::chrono::duration<double, std::milli> elapsed = now - get_last_rssi_meas_time();
        return elapsed > timeout_ms;
    }
    bool operator==(const station &other) const
    {
        return std::memcmp(this->get_mac().data(), other.get_mac().data(), ETH_ALEN) == 0;
    }
    // sum (x_1*w_1) + ... + (xn*wn) / sum(w_i)
    void calculate_wma()
    {
        static std::chrono::milliseconds reference_time = std::chrono::milliseconds(5000);
        auto now                                        = std::chrono::system_clock::now();

        int32_t rssi_sum = 0;
        int i            = 0;
        int denom        = 0;

        for (const auto &measurement : m_rssi_measurements) {
            std::chrono::duration<double, std::milli> time_diff =
                now - measurement.m_measurement_timestamp;
            auto weight = (reference_time - time_diff).count();
            if (weight < 0)
                continue;
            rssi_sum += (measurement.m_rssi_value * weight);
            denom += weight;
        }
        if (denom != 0)
            rssi_sum /= denom;
        std::cout << "wma " << rssi_sum << std::endl;
    }
};

static std::vector<station> stations;

/**
 * @brief Call 'cb' on every station in the station list
 * 
 * @tparam Callback 
 * @param cb the callback to call with a station passed in.
 */
template <typename Callback> void station_for_each(Callback cb)
{
    for (const station &sta : stations)
        cb(sta);
}

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

// only works for sub wifi 6 -- IEEE dudes are wrapping chan # back to 1 for 6GHz : - )
static int frequency_to_channel_number(int freq_)
{
    uint16_t channel = 0;
    // Channels 1 - 13
    if ((freq_ >= 2412) && (freq_ <= 2472)) {
        channel = (1 + ((freq_ - 2412) / 5));
    }
    // Channels 36 - 64
    else if ((freq_ >= 5170) && (freq_ <= 5320)) {
        channel = (34 + ((freq_ - 5170) / 5));
    }
    // Channels 100 - 144
    else if ((freq_ >= 5500) && (freq_ <= 5720)) {
        channel = (100 + ((freq_ - 5500) / 5));
    }
    // Channels 149 - 161
    else if ((freq_ >= 5745) && (freq_ <= 5805)) {
        channel = (149 + ((freq_ - 5745) / 5));
    }
    // Channel 165
    else if (freq_ == 5825) {
        channel = 165;
    }
    return (channel);
}

static void parse_radiotap_buf(struct ieee80211_radiotap_iterator &iter, const uint8_t *buf,
                               size_t buflen, radiotap_fields &rt_fields)
{
    // be careful of unaligned access!
    int err;
    while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
        switch (iter.this_arg_index) {
        case IEEE80211_RADIOTAP_TSFT:
            break;
        case IEEE80211_RADIOTAP_FLAGS:
            break;
        case IEEE80211_RADIOTAP_RATE:
            break;
        case IEEE80211_RADIOTAP_CHANNEL:
            rt_fields.channel_frequency = le16_to_cpu(*(uint16_t *)iter.this_arg);
            rt_fields.channel_number    = frequency_to_channel_number(rt_fields.channel_frequency);
            break;
        case IEEE80211_RADIOTAP_FHSS:
            break;
        case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
            rt_fields.rssi = (int8_t)*iter.this_arg;
            break;
        case IEEE80211_RADIOTAP_DBM_ANTNOISE:
            break;
        case IEEE80211_RADIOTAP_LOCK_QUALITY:
        case IEEE80211_RADIOTAP_TX_ATTENUATION:
        case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
        case IEEE80211_RADIOTAP_DBM_TX_POWER:
        case IEEE80211_RADIOTAP_ANTENNA:
        case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
            break;
        case IEEE80211_RADIOTAP_DB_ANTNOISE:
            break;
        case IEEE80211_RADIOTAP_TX_FLAGS:
            break;
        case IEEE80211_RADIOTAP_RTS_RETRIES:
        case IEEE80211_RADIOTAP_DATA_RETRIES:
            break;
            break;
        case IEEE80211_RADIOTAP_F_BADFCS:
            rt_fields.bad_fcs = true;
            break;
        default:
            break;
        }
    }

    if (err != -ENOENT) {
        printf("malformed radiotap data\n");
        return;
    }
}

// typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *,
// const u_char *);
static void packet_cb(u_char *args, const struct pcap_pkthdr *pcap_hdr, const u_char *packet)
{
    int err;
    int i;
    struct ieee80211_radiotap_iterator iter;

    err = ieee80211_radiotap_iterator_init(&iter, (ieee80211_radiotap_header *)packet, 2014, NULL);
    if (err) {
        printf("malformed radiotap header (init returns %d)\n", err);
        return;
    }
    const size_t eth_hdr_offset = iter._max_length;
    struct ieee80211_hdr *hdr   = (struct ieee80211_hdr *)(packet + eth_hdr_offset);
    if (std::find_if(std::begin(stations), std::end(stations), [&hdr](const station &sta) {
            return std::memcmp(sta.get_mac().data(), hdr->addr2, ETH_ALEN) == 0;
        }) == stations.end()) {
        stations.push_back(hdr->addr2);
    }

    stations.erase(std::remove_if(stations.begin(), stations.end(),
                                  [](const station &s) { return !s.is_potentially_mobile(); }),
                   stations.end());

    radiotap_fields rt_fields;
    parse_radiotap_buf(iter, (uint8_t *)packet, 2014, rt_fields);

    if (rt_fields.bad_fcs) {
        std::cout << "This radiotap sample is clapped." << std::endl;
        return;
    }

    auto sta_it = std::find_if(stations.begin(), stations.end(), [&hdr](const station &s) {
        return std::memcmp(s.get_mac().data(), hdr->addr2, ETH_ALEN) == 0;
    });
    // this shouldnt happen, but hey.
    if (sta_it == stations.end())
        return;
    sta_it->update_rt_fields(rt_fields);

    // DEBUG
    station_for_each([](const station &s) {
        printf("Station " MACSTRFMT ":", MAC2STR(s.get_mac().data()));
        std::cout << " RSSI: " << (int)s.get_rssi() << " ChannelNumber: " << s.get_channel()
                  << " ChannelFreq: " << s.get_frequency() << std::endl;
    });

    // do some housekeeping
    station_keepalive_check(stations, STATION_KEEPALIVE_TIMEOUT);

    station_for_each_mutable([](station &s) { s.calculate_wma(); });
    return;
}

int main(int argc, char **argv)
{
    std::cout << "Welcome to " << argv[0] << std::endl;
    if (argc < 3)
        print_usage_and([]() { exit(1); });
    std::string dev       = argv[1];
    int packet_cadence_ms = std::stoi(argv[2], 0, 10);
    char err[PCAP_ERRBUF_SIZE];
    auto pcap_handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, packet_cadence_ms, err);
    if (!pcap_handle) {
        std::cout << "Could not get a pcap handle on device '" << dev << "', pcap error: " << err
                  << std::endl;
        return 1;
    }
    std::cout << "Got a handle to device '" << dev << "'" << std::endl;
    pcap_loop(pcap_handle, 0, packet_cb, (u_char *)pcap_handle);
    pcap_close(pcap_handle);
    std::cout << "Bye!" << std::endl;
    return 0;
}