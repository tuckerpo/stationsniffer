#pragma once
#include <cstdint>
struct bandwidth_metadata {
    //  MHz
    uint8_t total_bandwidth;
    // -1 if unknown
    int8_t sideband;
    // -1 if unknown
    int8_t sideband_index;
};

// MCS rate and # spatial streams for VHT data
struct vht_mcs_nss {
    // Number of Spatial Streams
    uint8_t nss;
    // MCS index
    uint8_t mcs;
    // Number of Temporal Spatial Streams
    uint8_t nsts;
};

struct radiotap_fields {
    int8_t rssi{-127}; // dBm
    uint16_t channel_number;
    uint16_t channel_frequency; // mHz
    bool bad_fcs;               // bad frame control sequence, indicates that this is bogus data.
    vht_mcs_nss vht_mcs_nss_;
};
