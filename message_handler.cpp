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
        return handle_register_sta(header, request_fd);
    } break;
    case message_type_t::MSG_UNREGISTER_STA: {
        return handle_unregister_sta(header, request_fd);
    } break;
    case message_type_t::MSG_GET_STA_STATS: {
        return handle_get_sta_stats(header, request_fd);
    } break;
    case message_type_t::MSG_GET_STA_WMI_STATS: {
        return handle_get_sta_wmi_stats(header, request_fd);
    } break;
    case message_type_t::MSG_CHANGE_PACKET_PERIODICITY_MS:
        // fall thru
    case message_type_t::MSG_CHANGE_KEEPALIVE_TIMEOUT_MS:
        // fall thru
    default: {
        response_error_code = error_code_t::ERROR_BAD_MESSAGE;
        break;
    }
    }
    // error, or unknown message type.
    response.error_code = response_error_code;
    return send_message_response<decltype(response)>(response, request_fd);
}

bool message_handler::handle_register_sta(const message_request_header &header,
                                          int request_fd) const
{
    message_response_header response_out;
    m_sta_manager.register_station_of_interest(header.mac);
    response_out.error_code = error_code_t::ERROR_OK;
    return send_message_response<decltype(response_out)>(response_out, request_fd);
}

bool message_handler::handle_unregister_sta(const message_request_header &header,
                                            int request_fd) const
{
    message_response_header response_out;
    m_sta_manager.remove_station(header.mac);
    response_out.error_code = error_code_t::ERROR_OK;
    return send_message_response<decltype(response_out)>(response_out, request_fd);
}

bool message_handler::handle_get_sta_stats(const message_request_header &header,
                                           int request_fd) const
{
    sta_lm station_link_metrics_response{};
    auto maybe_station = m_sta_manager.get_sta_by_mac(header.mac);
    if (!maybe_station.has_value()) {
        station_link_metrics_response.response.error_code = error_code_t::ERROR_STA_NOT_KNOWN;
    } else {
        const station sta                                 = maybe_station.value();
        station_link_metrics_response.bandwidth           = sta.get_bandwidth();
        station_link_metrics_response.channel_number      = sta.get_channel();
        station_link_metrics_response.response.error_code = error_code_t::ERROR_OK;
        station_link_metrics_response.rssi                = sta.get_rssi();
        station_link_metrics_response.timestamp           = sta.get_last_seen_seconds();
    }
    return send_message_response<decltype(station_link_metrics_response)>(
        station_link_metrics_response, request_fd);
}

bool message_handler::handle_get_sta_wmi_stats(const message_request_header &header,
                                               int request_fd) const
{
    sta_wma_lm station_wma_link_metrics_response{};
    auto maybe_station = m_sta_manager.get_sta_by_mac(header.mac);
    if (!maybe_station.has_value()) {
        station_wma_link_metrics_response.response.error_code = error_code_t::ERROR_STA_NOT_KNOWN;
    } else {
        const station sta                                     = maybe_station.value();
        station_wma_link_metrics_response.bandwidth           = sta.get_bandwidth();
        station_wma_link_metrics_response.channel_number      = sta.get_channel();
        station_wma_link_metrics_response.response.error_code = error_code_t::ERROR_OK;
        station_wma_link_metrics_response.rssi                = sta.get_rssi();
        station_wma_link_metrics_response.wma_rssi            = sta.get_wma_rssi();
    }

    return send_message_response<decltype(station_wma_link_metrics_response)>(
        station_wma_link_metrics_response, request_fd);
}