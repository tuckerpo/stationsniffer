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
     * @brief Change the global keepalive timeout parameter.
     * 
     * The keepalive timeout is the threshold in milliseconds past which we consider a station 'dead' -- not heard from.
     * 
     */
    MSG_CHANGE_KEEPALIVE_TIMEOUT_MS = 0x10,
    /**
     * @brief Change how long we buffer packets before processing for. Mostly a tuning parameter for CPU load.
     * 
     */
    MSG_CHANGE_PACKET_PERIODICITY_MS = 0x20,
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
    uint64_t timestamp;
} __attribute__((packed));

struct sta_wma_lm : public response {
    sta_lm lm;
    int8_t wma_rssi;
} __attribute__((packed));

struct periodicity_message : public request {
    uint32_t periodicity_ms;
} __attribute__((packed));

static_assert(
    sizeof(sta_lm) == 15,
    "sta_lm struct should be 15 bytes (one byte for RSSI, 2 for channel number, 8 for timestamp)");
static_assert(
    sizeof(message_request_header) == 14,
    "message_header should be 14 bytes (uint32_t message_type, int8_t mac[6], uint32_t checksum");
static_assert(sizeof(periodicity_message) == 18,
              "struct periodicity_message should be 18 bytes long.");
static_assert(sizeof(sta_wma_lm) == 20, "struct sta_wma_lm should be 20 bytes long");
#endif // __MESSAGES_H
