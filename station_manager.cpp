#include "station_manager.h"
#include <iostream>

void station_manager::add_station(const uint8_t mac[ETH_ALEN])
{
    if (get_sta_by_mac(mac).has_value())
        return;
    auto lock = std::lock_guard<decltype(m_station_lock)>(m_station_lock);
    m_stations.push_back(station(mac));
}

void station_manager::remove_station(const uint8_t mac[ETH_ALEN])
{
    auto lock = std::lock_guard<decltype(m_station_lock)>(m_station_lock);
    m_stations.erase(std::remove_if(m_stations.begin(), m_stations.end(),
                                    [mac](const station &current_sta) -> bool {
                                        return std::memcmp(mac, current_sta.get_mac().data(),
                                                           ETH_ALEN) == 0;
                                    }),
                     m_stations.end());
    m_whitelisted_macs.erase(std::remove_if(m_whitelisted_macs.begin(), m_whitelisted_macs.end(),
                                            [mac](const whitelisted_mac &wl_mac) -> bool {
                                                return std::memcmp(wl_mac.get_mac().data(), mac,
                                                                   ETH_ALEN) == 0;
                                            }),
                             m_whitelisted_macs.end());
}

std::optional<station> station_manager::get_sta_by_mac(const uint8_t mac[ETH_ALEN]) const
{
    auto lock = std::lock_guard<decltype(m_station_lock)>(m_station_lock);
    const auto it =
        std::find_if(m_stations.begin(), m_stations.end(), [mac](const station &sta) -> bool {
            return std::memcmp(sta.get_mac().data(), mac, ETH_ALEN) == 0;
        });
    if (it != m_stations.end())
        return *it;
    // not found.
    return {};
}

bool station_manager::should_capture_all_traffic() const
{
    if (m_whitelisted_macs.empty())
        return false;

    bool is_at_least_one_whitelisted_mac_broadcast = false;
    for (const auto &wl_mac : m_whitelisted_macs) {
        if (std::all_of(wl_mac.get_mac().begin(), wl_mac.get_mac().end(),
                        [](const uint8_t &byte) -> bool { return 0xff == byte; })) {
            is_at_least_one_whitelisted_mac_broadcast = true;
        }
    }
    return is_at_least_one_whitelisted_mac_broadcast;
}

void station_manager::register_station_of_interest(const uint8_t sta_mac[ETH_ALEN])
{
    if (get_sta_by_mac(sta_mac).has_value())
        return;
    m_whitelisted_macs.push_back(whitelisted_mac(sta_mac));
}

bool station_manager::station_is_whitelisted(const uint8_t mac[ETH_ALEN])
{
    return std::find_if(m_whitelisted_macs.begin(), m_whitelisted_macs.end(),
                        [mac](const whitelisted_mac &wl_mac) -> bool {
                            return std::memcmp(wl_mac.get_mac().data(), mac, ETH_ALEN) == 0;
                        }) != m_whitelisted_macs.end();
}

bool station_manager::update_station_rt_fields(const uint8_t mac[ETH_ALEN],
                                               const radiotap_fields &rt_f)
{
    auto lock = std::lock_guard<decltype(m_station_lock)>(m_station_lock);
    auto it   = std::find_if(m_stations.begin(), m_stations.end(), [mac](const station &s) -> bool {
        return std::memcmp(s.get_mac().data(), mac, ETH_ALEN) == 0;
    });
    if (it == m_stations.end())
        return false;
    it->update_rt_fields(rt_f);
    return true;
}

bool station_manager::update_station_last_seen(const uint8_t mac[ETH_ALEN], time_t time_seconds)
{
    auto lock = std::lock_guard<decltype(m_station_lock)>(m_station_lock);
    auto it   = std::find_if(m_stations.begin(), m_stations.end(), [mac](const station &s) -> bool {
        return std::memcmp(s.get_mac().data(), mac, ETH_ALEN) == 0;
    });
    if (it == m_stations.end())
        return false;
    it->update_last_seen(time_seconds);
    return true;
}

void station_manager::set_bandwidth_for_sta(const uint8_t mac[ETH_ALEN], uint8_t new_bw)
{
    auto lock = std::lock_guard<decltype(m_station_lock)>(m_station_lock);
    auto it   = std::find_if(m_stations.begin(), m_stations.end(), [mac](const station &s) -> bool {
        return std::memcmp(s.get_mac().data(), mac, ETH_ALEN) == 0;
    });
    if (it == m_stations.end())
        return;
    it->set_bandwidth(new_bw);
}

void station_manager::add_disassociated_station(const uint8_t mac[ETH_ALEN],
                                                const uint8_t bssid[ETH_ALEN])
{
    std::array<uint8_t, ETH_ALEN> bssid_mac;
    std::copy_n(bssid, ETH_ALEN, bssid_mac.data());
    m_disassociated_stations.push_back(std::pair(station(mac), bssid_mac));
}

std::vector<std::pair<station, std::array<uint8_t, ETH_ALEN>>>
station_manager::get_disassociated_stations() const
{
    return m_disassociated_stations;
}
