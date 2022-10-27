#pragma once
#include <cstdint>

struct radiotap_fields {
    int8_t rssi; // dBm
    uint16_t channel_number;
    uint16_t channel_frequency; // mHz
    bool bad_fcs;               // bad frame control sequence, indicates that this is bogus data.
};