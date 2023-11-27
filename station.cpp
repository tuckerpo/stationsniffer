#include "station.h"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <sstream>

station::station(uint8_t mac[ETH_ALEN])
{
    for (size_t i = 0; i < ETH_ALEN; i++)
        m_mac[i] = mac[i];
    m_rssi_wma       = 0;
    m_last_seen_time = 0;
}

station::station(const uint8_t mac[ETH_ALEN])
{
    for (size_t i = 0; i < ETH_ALEN; i++)
        m_mac[i] = mac[i];
    m_rssi_wma       = 0;
    m_last_seen_time = 0;
}

station::station(const std::array<uint8_t, ETH_ALEN> &mac) : m_mac(mac)
{
    m_rssi_wma       = 0;
    m_last_seen_time = 0;
}

std::array<uint8_t, ETH_ALEN> station::get_mac() const { return m_mac; }

int8_t station::get_rssi() const { return m_rt_fields.rssi; }
// second nibble of MSB of MAC being 2, E, A or 6 seems to indicate mac randomization (which is canonically only implemented by mobile stations)

bool station::is_potentially_mobile() const
{
    return ((get_mac()[0] & 0x0f) == 0x0A) || ((get_mac()[0] & 0x0f) == 0x0E) ||
           ((get_mac()[0] & 0x0f) == 0x06) || ((get_mac()[0] & 0x0f) == 0x02);
}

void station::update_rt_fields(const radiotap_fields &rt_f)
{
    m_rt_fields = rt_f;
    m_rssi_measurements.push_back(
        {m_rt_fields.rssi, m_rt_fields.channel_number, std::chrono::system_clock::now()});
}

int16_t station::get_frequency() const { return m_rt_fields.channel_frequency; }
uint16_t station::get_channel() const { return m_rt_fields.channel_number; }
int8_t station::get_wma_rssi() const { return m_rssi_wma; }

bool station::is_timed_out_ms(std::chrono::milliseconds timeout_ms) const
{
    if (m_rssi_measurements.size() == 0)
        return false;
    time_t time_now_seconds   = std::time(nullptr);
    time_t time_delta_seconds = time_now_seconds - get_last_seen_seconds();
    return (time_delta_seconds * 1000 >= timeout_ms.count());
}
bool station::operator==(const station &other) const
{
    return std::memcmp(this->get_mac().data(), other.get_mac().data(), ETH_ALEN) == 0;
}

void station::calculate_wma()
{
    static std::chrono::milliseconds reference_time = std::chrono::milliseconds(5000);
    auto now                                        = std::chrono::system_clock::now();

    int32_t rssi_sum = 0;
    int denom        = 0;

    for (const auto &measurement : m_rssi_measurements) {
        std::chrono::duration<double, std::milli> time_diff =
            now - measurement.m_measurement_timestamp;
        auto weight = (reference_time - time_diff).count();
        if (weight < 0)
            continue;
        rssi_sum += (measurement.m_rssi_value * weight);
        denom += weight;
    }
    if (denom != 0)
        rssi_sum /= denom;
    m_rssi_wma = rssi_sum;
}

time_t station::get_last_seen_seconds() const { return m_last_seen_time; }

void station::update_last_seen(time_t time_sec) { m_last_seen_time = time_sec; }

bool station::addr_is_multicast() const
{
    return std::all_of(get_mac().begin(), get_mac().end(),
                       [](const auto &byte) -> bool { return 0xff == byte; });
}

void station::set_bandwidth(uint8_t bw) { m_bandwidth = bw; }

uint8_t station::get_bandwidth() const { return m_bandwidth; }

uint8_t station::get_vht_mcs_rate() const { return m_rt_fields.vht_mcs_nss_.mcs; }

uint8_t station::get_vht_nss() const { return m_rt_fields.vht_mcs_nss_.nss; }

uint8_t station::get_ant_noise() const { return m_rt_fields.ant_noise; }

bool station::measurement_period_elapsed() const
{
    time_t now   = std::time(nullptr);
    time_t delta = now - get_last_seen_seconds();
    fprintf(stdout, "Delta=%ld, period=%ld, last_seen=%ld\n", delta, m_bits_collection_period,
            get_last_seen_seconds());
    return delta >= m_bits_collection_period;
}

void station::bucketize_measurements()
{
    m_traffic_stat.n_inbound_bits_per_period  = m_traffic_stat.inbound_bytes * 8;
    m_traffic_stat.n_outbound_bits_per_period = m_traffic_stat.outbound_bytes * 8;
    m_traffic_stat.collection_period          = m_bits_collection_period;
    m_traffic_stats.push_back(m_traffic_stat);
    // Reset after it's been added to the list.
    m_traffic_stat = {0};
}

time_t station::get_measurement_period() const { return m_bits_collection_period; }

void station::dump_station_stats(const std::string &filename) const
{
    if (filename.empty())
        return;
    FILE *f = fopen(filename.c_str(), "ab+");
    if (!f) {
        std::cerr << "Could not open '" << filename << "'" << std::endl;
        return;
    }
    std::stringstream ss{};
    fprintf(f, "period,inbound_bits,outbound_bits\n");

    for (const auto &traffic_stat : m_traffic_stats) {
        fprintf(f, "%ld,%ld,%ld\n", traffic_stat.collection_period,
                traffic_stat.n_inbound_bits_per_period, traffic_stat.n_outbound_bits_per_period);
    }

    fclose(f);
}

void station::add_bytes(size_t n_bytes, traffic_direction_t direction) {
    switch (direction) {
        case traffic_direction_t::INBOUND:
            m_traffic_stat.inbound_bytes += n_bytes;
            break;
        case traffic_direction_t::OUTBOUND:
            m_traffic_stat.outbound_bytes += n_bytes;
            break;
        case traffic_direction_t::UNKNOWN:
            break;
    }
}