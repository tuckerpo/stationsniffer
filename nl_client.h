#pragma once
#include "nl80211_socket.h"
#include <array>
#include <cstdint>
#include <string>
#include <vector>

/**
 * @brief Struct to hold data about a wireless interface.
 * 
 */
struct if_info {
    if_info() = default;
    std::array<uint8_t, 6> mac;
    uint32_t wiphy;
    uint16_t frequency;
    uint16_t channel;
    uint16_t bandwidth;
    uint16_t frequency_center1;
    uint16_t frequency_center2;
};

class nl80211_client {
public:
    virtual ~nl80211_client() = default;

    /**
     * @brief Get metadata about an interface with name 'interface_name'
     * 
     * @param interface_name The name of the interface of interest
     * @param info[out] POD of interface metadata.
     * @return true on success, false and default-initialized info otherwise.
     */
    virtual bool get_interface_info(const std::string &interface_name, if_info &info) = 0;
};

class nl80211_client_impl : public nl80211_client {
    nl80211_socket *m_socket;

public:
    explicit nl80211_client_impl(nl80211_socket *socket);
    virtual ~nl80211_client_impl() = default;
    virtual bool get_interface_info(const std::string &interface_name, if_info &info) override;
    bool get_wiphy_bandwidth(if_info &info);

private:
    void get_bandwidth_from_attr(struct nlattr **tb, if_info &info);
};
