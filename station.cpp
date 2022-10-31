#include "station.h"
#include <cstring>

station::station(uint8_t mac[ETH_ALEN])
{
    for (size_t i = 0; i < ETH_ALEN; i++)
        m_mac[i] = mac[i];
}

station::station(const std::array<uint8_t, ETH_ALEN> &mac) { m_mac = mac; }
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
std::chrono::time_point<std::chrono::high_resolution_clock> station::get_last_rssi_meas_time() const
{
    return m_rssi_measurements.back().m_measurement_timestamp;
}
bool station::is_timed_out_ms(std::chrono::milliseconds timeout_ms) const
{
    if (m_rssi_measurements.size() == 0)
        return false;
    auto now                                          = std::chrono::system_clock::now();
    std::chrono::duration<double, std::milli> elapsed = now - get_last_rssi_meas_time();
    return elapsed > timeout_ms;
}
bool station::operator==(const station &other) const
{
    return std::memcmp(this->get_mac().data(), other.get_mac().data(), ETH_ALEN) == 0;
}
// sum (x_1*w_1) + ... + (xn*wn) / sum(w_i)
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
