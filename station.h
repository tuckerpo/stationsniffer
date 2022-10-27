#pragma once

#include "radiotap_fields.h"
#include "rssi_measurement.h"
#include <array>
#include <chrono>
#include <vector>

/**
 * @brief The length of a MAC address, in bytes.
 * 
 */
constexpr size_t ETH_ALEN = 6;

class station {
    radiotap_fields m_rt_fields;
    std::array<uint8_t, ETH_ALEN> m_mac;
    int8_t m_rssi_wma;
    // the end of this vector will contain the most recent instantaneous measurement.
    std::vector<rssi_measurement> m_rssi_measurements;

public:
    station(uint8_t mac[ETH_ALEN]);

    station(const std::array<uint8_t, ETH_ALEN> &mac);
    virtual ~station() = default;
    /**
     * @brief Get this station's MAC address.
     * 
     * @return std::array<uint8_t, ETH_ALEN> - the MAC.
     */
    std::array<uint8_t, ETH_ALEN> get_mac() const;
    /**
     * @brief Get the most recent RSSI measurement that has been made for this station.
     * 
     * @return int8_t the RSSI
     */
    int8_t get_rssi() const;

    /**
     * @brief Returns whether or not this station is _likely_ a mobile station (i.e. a cell phone, a laptop, tablet, etc)
     * 
     * The second nibble of the MSB of a station's MAC address being one of [0x2, 0xE, 0xA, 0x6] seems to indicate MAC randomization on the station.
     * Canonically, MAC randomization is only implemented for mobile stations, mostly phones.
     * 
     * @return true if this station is likely a mobile station.
     * @return false otherwise.
     */
    bool is_potentially_mobile() const;

    /**
     * @brief Update this station's parsed radiotap fields
     * 
     * @param rt_f The radiotap fields to read from.
     */
    void update_rt_fields(const radiotap_fields &rt_f);

    int16_t get_frequency() const;
    uint16_t get_channel() const;
    int8_t get_wma_rssi() const;
    /**
     * @brief Get the measurement time of the most recent RSSI reading. Used to check if a station is 'alive' still.
     * 
     * @return std::chrono::time_point<std::chrono::high_resolution_clock> the timestamp.
     */
    std::chrono::time_point<std::chrono::high_resolution_clock> get_last_rssi_meas_time() const;
    /**
     * @brief Determine if a station is alive still.
     * 
     * @param timeout_ms The timeout value (milliseconds) threshold. If there has not been a new RSSI measurement made for this station in `timeout_ms`, then it is considered timedout.
     * @return true if the station is timed out.
     * @return false otherwise.
     */
    bool is_timed_out_ms(std::chrono::milliseconds timeout_ms) const;
    bool operator==(const station &other) const;
    /**
     * @brief Computes the weighted average of RSSI values over this station's RSSI measurement list.
     * 
     * More recent measurements are weighed higher.
     * 
     * (x_1*w_1) + ... + (x_n*w_n) / sum(w_i) -- where x_i is an RSSI measurement value in dBm, and w_i is it's weight.
     */
    void calculate_wma();
};
