#include "messages.h"

std::string error_code_to_string(const error_code_t &err_code)
{
    switch (err_code) {
    case error_code_t::ERROR_STA_NOT_KNOWN:
        return "ERROR_STA_NOT_KNOWN";
    case error_code_t::ERROR_OK:
        return "ERROR_OK";
    case error_code_t::ERROR_BAD_MESSAGE:
        return "ERROR_BAD_MESSAGE";
    default:
        break;
    }
    return "Unknown error code";
}

std::string message_type_to_string(const message_type_t &mt)
{
    switch (mt) {
    case message_type_t::MSG_REGISTER_STA:
        return "MSG_REGISTER_STA";
    case message_type_t::MSG_UNREGISTER_STA:
        return "MSG_UNREGISTER_STA";
    case message_type_t::MSG_GET_STA_STATS:
        return "MSG_GET_STA_STATS";
    case message_type_t::MSG_GET_STA_WMI_STATS:
        return "MSG_GET_STA_WMI_STATS";
    case message_type_t::MSG_GET_DISASSOCIATED_STATIONS:
        return "MSG_GET_DISASSOCIATED_STATIONS";
    case message_type_t::MSG_GET_TRAFFIC_STATS_BUCKET_SIZE:
        return "MSG_GET_TRAFFIC_STATS_BUCKET_SIZE";
    case message_type_t::MSG_GET_TRAFFIC_STATS:
        return "MSG_GET_TRAFFIC_STATS";
    case message_type_t::MSG_ADJUST_TRAFFIC_STATS_BUCKET_SIZE:
        return "MSG_ADJUST_TRAFFIC_STATS_BUCKET_SIZE";
    default:
        break;
    }
    return "Unknown message type";
}
