#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string_view>
#include <array>
#include <vector>
#include <algorithm>
#include <cstring>

// rt stuff
#include "radiotap-library/radiotap.h"
#include "radiotap-library/radiotap_iter.h"
#include "radiotap-library/platform.h"

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
} __attribute__ ((packed));

template<typename Callback>
static void print_usage_and(Callback cb) {
    static constexpr std::string_view usage_str = "Usage: ./pcap <device>";
    std::cout << usage_str << std::endl;
    cb();
}

struct radiotap_fields
{
	int8_t rssi; // dBm
	uint16_t channel_number;
	uint16_t channel_frequency; // mHz
	bool bad_fcs; // bad frame control sequence, indicates that this is bogus crap.
};

class station
{
	radiotap_fields m_rt_fields;
	std::array<uint8_t, ETH_ALEN> m_mac;
	uint32_t m_rolling_rssi;
public:
	station(uint8_t mac[ETH_ALEN]) { for (int i = 0; i < ETH_ALEN; i++) m_mac[i] = mac[i]; }
	station(const std::array<uint8_t, ETH_ALEN>& mac) { m_mac = mac; }
	virtual ~station() = default;
	std::array<uint8_t, ETH_ALEN> get_mac() const { return m_mac; }
	int8_t get_rssi() const { return m_rt_fields.rssi; }
	// second nibble of MSB of MAC being 2, E, A or 6 seems to indicate mac randomization (which is canonically only implemented by mobile stations)
	bool is_potentially_mobile() const { return ((get_mac()[0] & 0x0f) == 0x0A) || ((get_mac()[0] & 0x0f) == 0x0E) || ((get_mac()[0] & 0x0f) == 0x06) || ((get_mac()[0] & 0x0f) == 0x02); }
	void update_rt_fields(const radiotap_fields& rt_f) {
		m_rt_fields = rt_f;
	}
	int16_t get_frequency() const { return m_rt_fields.channel_frequency; }
	uint16_t get_channel() const { return m_rt_fields.channel_number; }
};

static std::vector<station> stations;

template<typename Callback>
void station_for_each(Callback cb) {
	for (const station& sta : stations)
		cb(sta);
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

// typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *,
			     // const u_char *);
static void packet_cb(u_char * args, const struct pcap_pkthdr * pcap_hdr, const u_char * packet)
{
    int err;
    int i;
	struct ieee80211_radiotap_iterator iter;

    err = ieee80211_radiotap_iterator_init(&iter, (ieee80211_radiotap_header *) packet, 2014, NULL);
	if (err) {
		printf("malformed radiotap header (init returns %d)\n", err);
		return;
	}

    struct ieee80211_hdr *hdr =(struct ieee80211_hdr *)(packet + iter._max_length);
	if (std::find_if(std::begin(stations), std::end(stations), [&hdr](const station& sta){ return std::memcmp(sta.get_mac().data(), hdr->addr2, ETH_ALEN) == 0; }) == stations.end())
	{
		stations.push_back(station(hdr->addr2));
	}

	stations.erase(std::remove_if(stations.begin(), stations.end(), [](const station& s) { return !s.is_potentially_mobile(); }), stations.end());
	station_for_each([](const station& s) { 
		printf("Station " MACSTRFMT "\n", MAC2STR(s.get_mac().data())); 
		printf("\tchan #%d, chan freq %d (MHz), RSSI %d (dBm)\n", s.get_channel(), s.get_frequency(), s.get_rssi());
	});
	radiotap_fields rt_fields;

    /**
     * Parsing captured data packet and print radiotap information.
     */
    while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
	switch (iter.this_arg_index) {
	case IEEE80211_RADIOTAP_TSFT:
		// printf("\tTSFT: %llu\n", le64toh(*(unsigned long long *)iter.this_arg));
		break;
	case IEEE80211_RADIOTAP_FLAGS:
		// printf("\tflags: %02x\n", *iter.this_arg);
		break;
	case IEEE80211_RADIOTAP_RATE:
		// printf("\trate: %lf\n", (double)*iter.this_arg/2);
		break;
	case IEEE80211_RADIOTAP_CHANNEL:
		rt_fields.channel_frequency = le16_to_cpu(*(uint16_t*)iter.this_arg);
		rt_fields.channel_number = frequency_to_channel_number(rt_fields.channel_frequency);
		// printf("\tchannel frequency: %d\n", (u_int16_t)*iter.this_arg);
		break;
	case IEEE80211_RADIOTAP_FHSS:
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
		rt_fields.rssi = (int8_t)*iter.this_arg;
		// printf("\tdbm antsignal: %d\n", (int8_t)*iter.this_arg);
		break;
	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
		// printf("\tdbm antnoise: %d\n", (int8_t)*iter.this_arg);
		break;
	case IEEE80211_RADIOTAP_LOCK_QUALITY:
	case IEEE80211_RADIOTAP_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DBM_TX_POWER:
	case IEEE80211_RADIOTAP_ANTENNA:
	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
		// printf("\tdb antsignal: %d\n", (int8_t)*iter.this_arg);
		break;
	case IEEE80211_RADIOTAP_DB_ANTNOISE:
		// printf("\tdb antnoise: %d\n", (int8_t)*iter.this_arg);
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
		// printf("\tBOGUS DATA\n");
		break;
	}
	}

	if (err != -ENOENT) {
		printf("malformed radiotap data\n");
		return;
	}

	if (rt_fields.bad_fcs) {
		std::cout << "This radiotap sample is clapped." << std::endl;
		return;
	}

	auto sta_it = std::find_if(stations.begin(), stations.end(), [&hdr](const station& s) { return std::memcmp(s.get_mac().data(), hdr->addr2, ETH_ALEN) == 0; });
	// this shouldnt happen, but hey.
	if (sta_it == stations.end())
		return;
	sta_it->update_rt_fields(rt_fields);
	return;
}

int main(int argc, char **argv)
{
    std::cout << "Welcome to " << argv[0] << std::endl;
    if (argc < 2) print_usage_and([](){ exit(1); });
    std::string dev = argv[1];
    char err[PCAP_ERRBUF_SIZE];
    auto pcap_handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 100, err);
    if (!pcap_handle) {
        std::cout << "Could not get a pcap handle on device '" << dev << "', pcap error: " << err << std::endl;
        return 1;
    }
    std::cout << "Got a handle to device '" << dev << "'" << std::endl;
    pcap_loop(pcap_handle, 0, packet_cb, (u_char *)pcap_handle);
    pcap_close(pcap_handle);
    std::cout << "Bye!" << std::endl;
    return 0;
}