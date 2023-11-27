#pragma once

#include <cstdint>

// rt stuff
#include <platform.h>
#include <radiotap.h>
#include <radiotap_iter.h>

struct radiotap_fields;

/**
 * @brief Parse the radiotap header of a packet.
 * 
 * 
 * If `rt_fields` has `bad_fcs` set, then the output should be ignored.
 * 
 * @param iter The initialized radiotap iterator.
 * @param buf The radiotap header.
 * @param buflen The length of the radiotap header.
 * @param[out] rt_fields Radiotap fields of interest.
 */
void parse_radiotap_buf(struct ieee80211_radiotap_iterator &iter, const uint8_t *buf, size_t buflen,
                        radiotap_fields &rt_fields);
