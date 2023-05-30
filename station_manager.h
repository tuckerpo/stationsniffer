#pragma once

#include "radiotap_fields.h"
#include "station.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <vector>

/**
 * @brief Class for managing station lifetimes.
 */
class station_manager {
    /**
     * @brief Stations that we're measuring traffic on.
     */
    std::vector<station> m_stations;

    struct whitelisted_mac {
        std::array<uint8_t, ETH_ALEN> m_mac;
        explicit whitelisted_mac(uint8_t mac[ETH_ALEN])
        {
            for (size_t i = 0; i < ETH_ALEN; i++)
                m_mac[i] = mac[i];
        }
        explicit whitelisted_mac(const uint8_t mac[ETH_ALEN])
        {
            for (size_t i = 0; i < ETH_ALEN; i++)
                m_mac[i] = mac[i];
        }
        explicit whitelisted_mac(const std::array<uint8_t, ETH_ALEN> &mac) : m_mac(mac) {}
        std::array<uint8_t, ETH_ALEN> get_mac() const { return m_mac; }
    };

    /**
     * @brief MACs for stations that we want to measure link metrics on, but have not seen yet.
     */
    std::vector<whitelisted_mac> m_whitelisted_macs;

    /**
     * @brief Vector of pairs of <station_mac, BSSID> where BSSID is the BSS that the station has left.
     * 
     */
    std::vector<std::pair<station, std::array<uint8_t, ETH_ALEN>>> m_disassociated_stations;

    /**
     * @brief For atomic access when operating on stations.
     */
    mutable std::mutex m_station_lock;

public:
    station_manager()          = default;
    virtual ~station_manager() = default;

    /**
     * @brief Create and track a station object
     *
     * @param mac The MAC of the station object to create.
     *
     * If we see traffic from a whitelisted MAC address, we begin tracking it's lifetime and link
     * metrics as a station object here.
     */
    void add_station(const uint8_t mac[ETH_ALEN]);

    /**
     * @brief Stops measurement of a station, and removes it from the whitelist.
     *
     * @param mac The MAC of the station to remove.
     *
     * Note: removing a station removes RSSI measurement history.
     */
    void remove_station(const uint8_t mac[ETH_ALEN]);

    /**
     * @brief Returns a station object keyed by MAC address.
     *
     * @param mac The station MAC of interest.
     *
     * @return std::optional<station> A station object correlated to mac, if found, or an empty
     * optional otherwise.
     */
    std::optional<station> get_sta_by_mac(const uint8_t mac[ETH_ALEN]) const;

    /**
     * @brief Whether or not we should capture all traffic and derive link metrics from it, or only
     * capture link metrics for registered stations.
     *
     * @return true if at least one entry in the whitelisted MAC table is broadcast
     * (ff:ff:ff:ff:ff:ff), false otherwise.
     */
    bool should_capture_all_traffic() const;

    /**
     * @brief Registers a MAC as client of interest.
     *
     * If we see traffic from any client of interest, we will collect link metrics from it.
     *
     * @param sta_mac The unassociated station MAC to register to listen for.
     */
    void register_station_of_interest(const uint8_t sta_mac[ETH_ALEN]);

    /**
     * @brief Check if a given MAC address should be measured.
     *
     * @param mac The MAC addr of interest
     * @return true if mac is whitelisted, false otherwise
     */
    bool station_is_whitelisted(const uint8_t mac[ETH_ALEN]);

    /**
     * @brief Update a station's radiotap fields.
     *
     * @param mac The station to update.
     * @param rt_f The station's new radiotap fields.
     *
     * @return true if the station's radiotap fields were updated, false otherwise.
     */
    bool update_station_rt_fields(const uint8_t mac[ETH_ALEN], const radiotap_fields &rt_f);

    /**
     * @brief Update a station's "last seen" time -- the time we last saw a packet from them.
     *
     * @param mac The station MAC to update.
     *
     * @param time_seconds The time in seconds that we last saw this station at (relative to Unix
     * time).
     *
     * @return true if we could update the station's last seen time, false otherwise.
     */
    bool update_station_last_seen(const uint8_t mac[ETH_ALEN], time_t time_seconds);

    /**
     * @brief Set the bandwidth of the radio that made a measurement for a STA.
     * 
     * @param mac The MAC addr of the station to update.
     * @param new_bw The new bandwidth value.
     */
    void set_bandwidth_for_sta(const uint8_t mac[ETH_ALEN], uint8_t new_bw);

    /**
     * @brief Add a disassociated station to this manager's disassociated list.
     * 
     * @param mac The MAC of the station that disassociated.
     */
    void add_disassociated_station(const uint8_t mac[ETH_ALEN], const uint8_t bssid[ETH_ALEN]);

    /**
     * @brief Get the disassociated stations list
     * 
     * @return std::vector<station> A list of all disassociated stations.
     */
    std::vector<std::pair<station, std::array<uint8_t, ETH_ALEN>>>
    get_disassociated_stations() const;

    /**
     * @brief Calls 'Callback' on every station, immutable.
     *
     * @tparam Callback the callback to call on every station known to the station manager.
     */
    template <typename Callback> void for_each_station(Callback callback)
    {
        auto lock = std::lock_guard<decltype(m_station_lock)>(m_station_lock);
        for (const auto &station : m_stations)
            callback(station);
    }

    /**
     * @brief Calls 'Callback' on every station, mutable.
     *
     * @tparam Callback the callback to call on every station known to the station manager.
     */
    template <typename Callback> void for_each_station_mutable(Callback callback)
    {
        auto lock = std::lock_guard<decltype(m_station_lock)>(m_station_lock);
        for (auto &station : m_stations)
            callback(station);
    }
};
