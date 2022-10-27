#pragma once
#include <chrono>
/**
 * @brief Struct to hold metadata about an RSSI measurement.
 */
struct rssi_measurement {
    /**
     * @brief The RSSI value (usually, log-scale negative dBm)
     * 
     */
    int8_t m_rssi_value;
    /**
     * @brief The channel number on which the RSSI measurement was made.
     * 
     */
    uint16_t m_measurement_channel;
    /**
     * @brief The timestamp of this measurement.
     * 
     */
    std::chrono::time_point<std::chrono::high_resolution_clock> m_measurement_timestamp;
};