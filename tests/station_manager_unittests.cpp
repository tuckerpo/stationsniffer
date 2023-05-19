#include "../station_manager.h"
#include "gtest/gtest.h"

// Helper function to compare MAC addresses
bool compare_mac(const uint8_t mac1[ETH_ALEN], const uint8_t mac2[ETH_ALEN])
{
    return std::memcmp(mac1, mac2, ETH_ALEN) == 0;
}

TEST(StationManagerTest, AddStation)
{
    station_manager manager;

    // Add a station
    uint8_t mac[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    manager.add_station(mac);

    // Check if the station was added successfully
    ASSERT_TRUE(manager.get_sta_by_mac(mac).has_value() &&
                compare_mac(mac, manager.get_sta_by_mac(mac).value().get_mac().data()));
}

TEST(StationManagerTest, RemoveStation)
{
    station_manager manager;

    // Add a station
    uint8_t mac[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    manager.add_station(mac);

    // Remove the station
    manager.remove_station(mac);

    // Check if the station was removed successfully
    ASSERT_FALSE(manager.get_sta_by_mac(mac).has_value());
}

TEST(StationManagerTest, GetStationByMac)
{
    station_manager manager;

    // Add a station
    uint8_t mac[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    manager.add_station(mac);

    // Retrieve the station by MAC address
    std::optional<station> retrievedStation = manager.get_sta_by_mac(mac);

    // Check if the retrieved station is the same as the added station
    ASSERT_TRUE(retrievedStation.has_value());
    ASSERT_TRUE(compare_mac(retrievedStation->get_mac().data(), mac));
}

TEST(StationManagerTest, ShouldCaptureAllTraffic)
{
    station_manager manager;

    // No whitelisted MACs, should not capture all traffic
    ASSERT_FALSE(manager.should_capture_all_traffic());

    // Add a whitelisted MAC (broadcast address), should capture all traffic
    uint8_t broadcastMac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    manager.register_station_of_interest(broadcastMac);
    ASSERT_TRUE(manager.should_capture_all_traffic());

    // After, add a non-broadcast whitelisted MAC. Broadcast MAC should still be in the manager's
    // capture table, so should still capture all traffic.
    uint8_t mac[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    manager.register_station_of_interest(mac);
    ASSERT_TRUE(manager.should_capture_all_traffic());
}

TEST(StationManagerTest, ShouldCaptureAllTrafficPostRemoval)
{
    station_manager manager;

    // No registered stations, should be false.
    ASSERT_FALSE(manager.should_capture_all_traffic());

    uint8_t broadcast_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    manager.register_station_of_interest(broadcast_mac);

    // Broadcast MAC has been registered, should capture all traffic.
    ASSERT_TRUE(manager.should_capture_all_traffic());

    manager.remove_station(broadcast_mac);

    // Broadcast MAC has been removed, should not capture all traffic.
    ASSERT_FALSE(manager.should_capture_all_traffic());
}

TEST(StationManagerTest, RegisterStationOfInterest)
{
    station_manager manager;

    // Register a station of interest
    uint8_t staMac[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    manager.register_station_of_interest(staMac);

    // Check if the station of interest is registered successfully
    ASSERT_TRUE(manager.station_is_whitelisted(staMac));
}

TEST(StationManagerTest, UpdateStationRtFields)
{
    station_manager manager;

    // Add a station
    uint8_t mac[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    manager.add_station(mac);

    // Update the station's radiotap fields
    radiotap_fields rtFields;
    rtFields.rssi = 1;
    manager.update_station_rt_fields(mac, rtFields);

    // Retrieve the station and check if the radiotap fields were updated
    std::optional<station> retrievedStation = manager.get_sta_by_mac(mac);
    ASSERT_TRUE(retrievedStation.has_value());
    ASSERT_EQ(retrievedStation->get_rssi(), 1);
}

TEST(StationManagerTest, UpdateStationLastSeen)
{
    station_manager manager;

    // Add a station
    uint8_t mac[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    manager.add_station(mac);

    // Update the station's last seen time
    time_t currentTime = time(nullptr);
    manager.update_station_last_seen(mac, currentTime);

    // Retrieve the station and check if the last seen time was updated
    std::optional<station> retrievedStation = manager.get_sta_by_mac(mac);
    ASSERT_TRUE(retrievedStation.has_value());
    ASSERT_EQ(retrievedStation->get_last_seen_seconds(), currentTime);
}

TEST(StationManagerTest, SetBandwidthForStation)
{
    station_manager manager;

    // Add a station
    uint8_t mac[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    manager.add_station(mac);

    // Set the bandwidth for the station
    uint8_t bandwidth = 20;
    manager.set_bandwidth_for_sta(mac, bandwidth);

    // Retrieve the station and check if the bandwidth was set
    std::optional<station> retrievedStation = manager.get_sta_by_mac(mac);
    ASSERT_TRUE(retrievedStation.has_value());
    ASSERT_EQ(retrievedStation->get_bandwidth(), bandwidth);
}

// Define additional tests as needed

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
