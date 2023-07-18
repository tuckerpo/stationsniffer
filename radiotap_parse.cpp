#include "radiotap_parse.h"
#include "radiotap_fields.h"
#include <cassert>
#include <map>
#include <vector>

#define BIT(n) (1 << n)
#define STBC_BIT BIT(0)

/**
 * @brief Convert a sub-WiFi 6 frequency (MHz) to channel number.
 *
 * Note: only works for sub-WiFi 6, as the IEEE folks are wrapping channel numbers back to 1 for the 6 GHz band.
 *
 * @param freq_ Frequency, in megahertz (MHz)
 * @return int the channel number. Will be zero if the frequency conversion is unknown.
 */
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

bandwidth_metadata parse_radiotap_bandwidth(uint8_t radiotap_bw_data)
{
    // static data, just gen once for fast lookup
    static std::map<int, bandwidth_metadata> lookup_table;
    lookup_table[0]  = {20, -1, -1};
    lookup_table[1]  = {40, -1, -1};
    lookup_table[2]  = {40, 20, 0};
    lookup_table[3]  = {40, 20, 1};
    lookup_table[4]  = {80, -1, -1};
    lookup_table[5]  = {80, 40, 0};
    lookup_table[6]  = {80, 40, 1};
    lookup_table[7]  = {80, 20, 0};
    lookup_table[8]  = {80, 20, 1};
    lookup_table[9]  = {80, 20, 2};
    lookup_table[10] = {80, 20, 3};
    lookup_table[11] = {160, -1, -1};
    lookup_table[12] = {160, 80, 0};
    lookup_table[13] = {160, 80, 1};
    lookup_table[14] = {160, 40, 0};
    lookup_table[15] = {160, 40, 1};
    lookup_table[16] = {160, 40, 2};
    lookup_table[17] = {160, 40, 3};
    lookup_table[18] = {160, 20, 0};
    lookup_table[19] = {160, 20, 1};
    lookup_table[20] = {160, 20, 2};
    lookup_table[21] = {160, 20, 3};
    lookup_table[22] = {160, 20, 4};
    lookup_table[23] = {160, 20, 5};
    lookup_table[24] = {160, 20, 6};
    lookup_table[25] = {160, 20, 7};
    assert(radiotap_bw_data < lookup_table.size());
    return lookup_table[radiotap_bw_data];
}

vht_mcs_nss parse_radiotap_vht_mcs_nss(uint8_t radiotap_vht_mcs_nss, uint8_t flags)
{
    vht_mcs_nss parsed{};
    parsed.nss = radiotap_vht_mcs_nss & 0x0f;
    // Radiotap encodes a decimal MCS index as the high nibble in the MCS/NSS hex field.
    parsed.mcs = (radiotap_vht_mcs_nss & 0xf0) >> 4;
    // the number of space-time streams (NSTS) for a user can be calculated from the NSS for
    // that user and the STBC flag:
    (flags & STBC_BIT) ? (parsed.nsts = (2 * parsed.nss)) : (parsed.nsts = parsed.nss);
    return parsed;
}

void parse_radiotap_buf(struct ieee80211_radiotap_iterator &iter, const uint8_t *buf, size_t buflen,
                        radiotap_fields &rt_fields)
{
    // be careful of unaligned access!

    // typically, you only want the measurement made on the first antenna
    // for example, a 4 antenna phone will see something like:
    // ant1: -43 dBm, ant2: -45dBm, ant3: -99 dBm, ant4: -99 dBm
    int current_ant = 0;
    int err;
    while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
        switch (iter.this_arg_index) {
        case IEEE80211_RADIOTAP_FLAGS:
            rt_fields.bad_fcs = (uint8_t)*iter.this_arg & IEEE80211_RADIOTAP_F_BADFCS;
            break;
        case IEEE80211_RADIOTAP_CHANNEL:
            rt_fields.channel_frequency = le16_to_cpu(*(uint16_t *)iter.this_arg);
            rt_fields.channel_number    = frequency_to_channel_number(rt_fields.channel_frequency);
            break;
        case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
            // Only want the first measurement per packet (antenna 1, 0-indexed).
            if (0 == current_ant)
                rt_fields.rssi = (int8_t)*iter.this_arg;
            break;
        case IEEE80211_RADIOTAP_RATE:
            // The rate field reports the rx/tx data rate in units of 500 kbps
            // This field is generally considered unreliable.
            // The radiotap header reports ~1.6 Mbps on a fully saturated 802.11ac stream
            // See:  https://gitlab.com/wireshark/wireshark/-/issues/5280
            // Don't use this metric for any serious work.
            break;
        case IEEE80211_RADIOTAP_MCS: {
            [[maybe_unused]] uint8_t known = iter.this_arg[0];
            [[maybe_unused]] uint8_t flags = iter.this_arg[1];
            [[maybe_unused]] uint8_t mcs   = iter.this_arg[2];
        } break;
        case IEEE80211_RADIOTAP_VHT: {
            std::vector<vht_mcs_nss> vht_mcs_nss_list;
            // u16 known, u8 flags, u8 bandwidth, u8 vht_mcs_nss[4], u8 coding, u8 group_id, u16 partial_aid
            uint8_t bw            = iter.this_arg[3] & 0x1f;
            rt_fields.bw_metadata = parse_radiotap_bandwidth(bw);
            uint8_t flags         = iter.this_arg[2];
            for (int i = 4; i < 8; i++) {
                vht_mcs_nss_list.push_back(parse_radiotap_vht_mcs_nss(iter.this_arg[i], flags));
            }
            for (int i = 0; i < (int)vht_mcs_nss_list.size(); i++) {
                // If MCS index is zero, there's no data there.
                if (vht_mcs_nss_list[i].mcs > 0) {
                    rt_fields.vht_mcs_nss_ = vht_mcs_nss_list[i];
                }
            }
            break;
        }
        case IEEE80211_RADIOTAP_TSFT:
        case IEEE80211_RADIOTAP_FHSS:
        case IEEE80211_RADIOTAP_DBM_ANTNOISE:
            rt_fields.ant_noise = (uint8_t)iter.this_arg[0];
            break;
        case IEEE80211_RADIOTAP_LOCK_QUALITY:
        case IEEE80211_RADIOTAP_TX_ATTENUATION:
        case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
        case IEEE80211_RADIOTAP_DBM_TX_POWER:
        case IEEE80211_RADIOTAP_ANTENNA: {
            current_ant = iter.this_arg[0];
        } break;
        case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
        case IEEE80211_RADIOTAP_DB_ANTNOISE:
        case IEEE80211_RADIOTAP_TX_FLAGS:
        case IEEE80211_RADIOTAP_RTS_RETRIES:
        case IEEE80211_RADIOTAP_DATA_RETRIES:
        default:
            break;
        }
    }

    if (err != -ENOENT) {
        return;
    }
}
