#include "radiotap_parse.h"
#include "radiotap_fields.h"

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

void parse_radiotap_buf(struct ieee80211_radiotap_iterator &iter, const uint8_t *buf, size_t buflen,
                        radiotap_fields &rt_fields)
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
        return;
    }
}