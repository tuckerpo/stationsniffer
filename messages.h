#ifndef __MESSAGES_H
#define __MESSAGES_H
#include <assert.h>
#include <cinttypes>
#include <string>

enum class message_type_t : uint32_t {
    /**
     * @brief To register a station of interest (i.e. this process will begin monitoring and collect link metrics if that STA is seen.)
     * 
     */
    MSG_REGISTER_STA = 0x01,
    /**
     * @brief Unregister a station. Stop collecting metrics for this station. Pre-collected metrics, if any, will be lost.
     * 
     */
    MSG_UNREGISTER_STA = 0x02,
    /**
     * @brief Get the link metric statistics for a station.
     * 
     */
    MSG_GET_STA_STATS = 0x04,
    /**
     * @brief Get the link metric statistics for this station, but with the RSSI being a weighted mean average with more recent measurement weighed more.
     * 
     */
    MSG_GET_STA_WMI_STATS = 0x08,

    /**
     * @brief Get the traffic stats for a given station.
     *
     */
    MSG_GET_TRAFFIC_STATS = 0x10,

    /**
     * @brief Get the size (width) of a bucket.
     *
     */
    MSG_GET_TRAFFIC_STATS_BUCKET_SIZE = 0x20,

    /**
     * @brief Check if a given STA has disassociated from a BSS.
     * The STA MAC included in the message header is the station of interest.
     */
    MSG_GET_DISASSOCIATED_STATIONS = 0x40,

    /**
     * @brief Adjust the width of the bucket for a station.
     *
     */
    MSG_ADJUST_TRAFFIC_STATS_BUCKET_SIZE = 0x80,

};

enum class error_code_t : uint32_t {
    /**
     * @brief No error! Good to go.
     * 
     *
     */
    ERROR_OK = 0x00,
    /**
     * @brief The station that was request to act upon is not known to this Agent.
     * 
     */
    ERROR_STA_NOT_KNOWN = 0x01,
    /**
     * @brief Client fed us a malformed message.
     * 
     */
    ERROR_BAD_MESSAGE = 0x02,
};

enum class bandwidth_t : uint8_t {
    /**
     * @brief Unknown bandwidth -- default value
     * 
     */
    BANDWIDTH_UNKNOWN = 0,
    /**
     * @brief 20 mHz BW
     * 
     */
    BANDWIDTH_20MHZ = 20,
    /**
     * @brief 40 mHz BW
     * 
     */
    BANDWIDTH_40MHZ = 40,
    /**
     * @brief 80 mHz BW
     * 
     */
    BANDWIDTH_80MHZ = 80,
    /**
     * @brief 160 mHz BW
     * 
     */
    BANDWIDTH_160MHZ = 160,
    /**
     * @brief 80+80 mHz BW
     * 
     */
    BANDWIDTH_80_80 = 161,
};

/**
 * @brief Convert an error_code_t to a string literal
 * 
 * @param err_code the error_code_t of interest
 * @return std::string the string representation of 'err_code'
 */
extern std::string error_code_to_string(const error_code_t &err_code);

/**
 * @brief Convert a message_type_t enum to a string literal
 * 
 * @param mt the message_type_t of interest
 * @return std::string the string representation of 'mt'
 */
extern std::string message_type_to_string(const message_type_t &mt);

struct message_request_header {
    message_type_t message_type;
    uint8_t mac[6];
    uint32_t checksum;
} __attribute__((packed));

struct message_response_header {
    error_code_t error_code;
} __attribute__((packed));
struct request {
    message_request_header header;
} __attribute__((packed));

struct response {
    message_response_header response;
} __attribute__((packed));

struct sta_lm : public response {
    int8_t rssi;
    int16_t channel_number;
    uint8_t bandwidth;
    uint64_t timestamp;
} __attribute__((packed));

struct sta_wma_lm : public response {
    int8_t rssi;
    int16_t channel_number;
    uint8_t bandwidth;
    uint64_t timestamp;
    int8_t wma_rssi;
} __attribute__((packed));

struct sta_diassoc_query : public request {
};

struct sta_disassoc_response : public response {
    uint8_t disassociated;
    uint8_t bssid[6];
} __attribute__((packed));

static_assert(sizeof(sta_lm) == 16, "sta_lm struct should be 15 bytes (one byte for RSSI, 1 for "
                                    "bandwidth, 2 for channel number, 8 for timestamp)");
static_assert(
    sizeof(message_request_header) == 14,
    "message_header should be 14 bytes (uint32_t message_type, int8_t mac[6], uint32_t checksum");
static_assert(sizeof(sta_wma_lm) == 17, "struct sta_wma_lm should be 17 bytes long");
#endif // __MESSAGES_H
