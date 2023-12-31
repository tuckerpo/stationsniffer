#include "message_handler.h"
#include <iostream>
#include <sys/socket.h>

/**
 * @brief Send a response.
 * 
 * @tparam T the message response type
 * @param response the message reponse
 * @param fd the file descriptor to send to
 * @return true if send() succeeds
 * @return false otherwise
 */
template <typename T> static bool send_message_response(const T &response, int fd)
{
    // MSG_NOSIGNAL so we don't get SIGPIPE'd if a client hangs up.
    return (send(fd, &response, sizeof(T), MSG_NOSIGNAL) != -1);
}

message_handler::message_handler(station_manager &sta_manager) : m_sta_manager(sta_manager) {}

bool message_handler::post_data(const std::vector<uint8_t> &payload, int from_fd) const
{
    if (payload.empty() || (payload.size() < sizeof(message_request_header)))
        return false;
    message_request_header header;
    // We only need the header information, not the entire payload.
    // So, only take payload[0..sizeof(message_request_header)], and toss the rest.
    memcpy(&header, payload.data(), sizeof(message_request_header));
    return handle_message(header, from_fd);
}

bool message_handler::handle_message(const message_request_header &header, int request_fd) const
{
    message_response_header response;
    error_code_t response_error_code = error_code_t::ERROR_OK;
    switch (header.message_type) {
    case message_type_t::MSG_REGISTER_STA: {
        m_sta_manager.register_station_of_interest(header.mac);
    } break;
    case message_type_t::MSG_UNREGISTER_STA: {
        m_sta_manager.remove_station(header.mac);
    } break;
    case message_type_t::MSG_GET_STA_STATS: {
        sta_lm station_link_metrics{};
        auto sta = m_sta_manager.get_sta_by_mac(header.mac);
        if (sta.has_value()) {
            const station s                          = sta.value();
            station_link_metrics.rssi                = s.get_rssi();
            station_link_metrics.channel_number      = s.get_channel();
            station_link_metrics.bandwidth           = s.get_bandwidth();
            station_link_metrics.timestamp           = s.get_last_seen_seconds();
            station_link_metrics.response.error_code = error_code_t::ERROR_OK;
        } else {
            response_error_code = error_code_t::ERROR_STA_NOT_KNOWN;
            break;
        }
        return send_message_response<sta_lm>(station_link_metrics, request_fd);
    } break;
    case message_type_t::MSG_GET_STA_WMI_STATS: {
        sta_wma_lm station_wma_link_metrics{};
        auto sta = m_sta_manager.get_sta_by_mac(header.mac);
        if (sta.has_value()) {
            const station s                              = sta.value();
            station_wma_link_metrics.rssi                = s.get_rssi();
            station_wma_link_metrics.channel_number      = s.get_channel();
            station_wma_link_metrics.timestamp           = s.get_last_seen_seconds();
            station_wma_link_metrics.wma_rssi            = s.get_wma_rssi();
            station_wma_link_metrics.bandwidth           = s.get_bandwidth();
            station_wma_link_metrics.response.error_code = error_code_t::ERROR_OK;
        } else {
            response_error_code = error_code_t::ERROR_STA_NOT_KNOWN;
            break;
        }
        return send_message_response<sta_wma_lm>(station_wma_link_metrics, request_fd);
    } break;
    case message_type_t::MSG_GET_DISASSOCIATED_STATIONS: {
        auto disassociated_stations = m_sta_manager.get_disassociated_stations();
        sta_disassoc_response sta_dc_response{};
        auto sta_dc_it =
            std::find_if(disassociated_stations.begin(), disassociated_stations.end(),
                         [&header](const auto &sta_bssid_pair) -> bool {
                             auto sta = sta_bssid_pair.first;
                             return std::memcmp(sta.get_mac().data(), header.mac, ETH_ALEN) == 0;
                         });
        sta_dc_response.disassociated = (sta_dc_it != disassociated_stations.end());
        if (sta_dc_response.disassociated) {
            std::copy_n(sta_dc_it->second.data(), ETH_ALEN, sta_dc_response.bssid);
        }
        return send_message_response<sta_disassoc_response>(sta_dc_response, request_fd);
    } break;
    default: {
        response_error_code = error_code_t::ERROR_BAD_MESSAGE;
        break;
    }
    }
    // error, or unknown message type.
    response.error_code = response_error_code;
    return send_message_response<decltype(response)>(response, request_fd);
}
