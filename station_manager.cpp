#include "station_manager.h"
#include <iostream>

void station_manager::add_station(const uint8_t mac[ETH_ALEN])
{
    if (get_sta_by_mac(mac).has_value())
        return;
    m_stations.push_back(station(mac));
}

void station_manager::remove_station(const uint8_t mac[ETH_ALEN])
{
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

    for (const auto &wl_mac : m_whitelisted_macs)
        for (size_t i = 0; i < m_whitelisted_macs.size(); i++)
            if (0xff != wl_mac.get_mac()[i])
                return false;
    return true;
};

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
    auto it = std::find_if(m_stations.begin(), m_stations.end(), [mac](const station &s) -> bool {
        return std::memcmp(s.get_mac().data(), mac, ETH_ALEN) == 0;
    });
    if (it == m_stations.end())
        return false;
    it->update_rt_fields(rt_f);
    return true;
}

bool station_manager::update_station_last_seen(const uint8_t mac[ETH_ALEN], time_t time_seconds)
{
    auto it = std::find_if(m_stations.begin(), m_stations.end(), [mac](const station &s) -> bool {
        return std::memcmp(s.get_mac().data(), mac, ETH_ALEN) == 0;
    });
    if (it == m_stations.end())
        return false;
    it->update_last_seen(time_seconds);
    return true;
}

void station_manager::prune_timedout_stations(std::chrono::milliseconds timeout_ms)
{
    for (auto it = m_stations.begin(); it != m_stations.end();) {
        if (it->is_timed_out_ms(timeout_ms)) {
            it = m_stations.erase(it);
        } else {
            ++it;
        }
    }
}
