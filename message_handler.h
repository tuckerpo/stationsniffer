#pragma once

#include "messages.h"
#include "station_manager.h"
#include <vector>

/**
 * @brief Class for handling incoming messages
 */
class message_handler {
    station_manager &m_sta_manager;

    /**
     * @brief Handles an incoming request.
     *
     * @param header The message header.
     * @praram request_fd The file desctiptor this request came from.
     *
     * @return true if the message was handled, false otherwise.
     */
    bool handle_message(const message_request_header &header, int request_fd) const;

    bool handle_register_sta(const message_request_header &header, int request_fd) const;
    bool handle_unregister_sta(const message_request_header &header, int request_fd) const;
    bool handle_get_sta_stats(const message_request_header &header, int request_fd) const;
    bool handle_get_sta_wmi_stats(const message_request_header &header, int request_fd) const;

public:
    explicit message_handler(station_manager &sta_manager);
    virtual ~message_handler() = default;

    /**
     * @brief Post opaque data to this handler for processing.
     *
     * @param payload raw byte payload
     * @param from_fd The FD this data came from.
     */
    bool post_data(const std::vector<uint8_t> &payload, int from_fd) const;
};
