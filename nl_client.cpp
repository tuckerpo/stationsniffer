#include "nl_client.h"
#include <cstring>
#include <iostream>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <linux/version.h>
#include <net/if.h>
#include <netlink/genl/genl.h>

static std::string nl80211_parse_ifname(struct nlattr *tb[])
{
    std::string ifname{};
    if (tb[NL80211_ATTR_IFNAME]) {
        size_t len       = nla_len(tb[NL80211_ATTR_IFNAME]);
        const char *data = static_cast<const char *>(nla_data(tb[NL80211_ATTR_IFNAME]));
        if (0 == len) {
            std::cerr << "Interface name is empty\n";
        }
        if (data[len - 1] != '\0') {
            std::cerr << "Interface name is not null-terminated\n";
        }
        ifname.assign(data);
    }
    return ifname;
}

nl80211_client_impl::nl80211_client_impl(nl80211_socket *socket) : m_socket(socket) {}

bool nl80211_client_impl::get_interfaces(std::vector<std::string> &interfaces)
{
    if (!interfaces.empty())
        interfaces.clear();
    if (!m_socket) {
        std::cerr << "nl80211 socket is nullptr\n";
        return false;
    }

    return m_socket->send_receive_msg(
        NL80211_CMD_GET_INTERFACE, NLM_F_DUMP, [](struct nl_msg *msg) -> bool { return true; },
        [&](struct nl_msg *msg) {
            struct nlattr *tb[NL80211_ATTR_MAX + 1];
            struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));

            // Parse the netlink message
            if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
                          NULL)) {
                std::cerr << "Failed to parse netlink message NL80211_CMD_GET_INTERFACE\n";
                return;
            }

            std::string ifname = nl80211_parse_ifname(tb);
            if (!ifname.empty()) {
                interfaces.push_back(ifname);
            }
        });
}

void nl80211_client_impl::get_bandwidth_from_attr(struct nlattr **tb, if_info &info)
{
    if (tb[NL80211_ATTR_WIPHY_FREQ]) {
        info.frequency = nla_get_u32(tb[NL80211_ATTR_WIPHY_FREQ]);
        if (tb[NL80211_ATTR_CHANNEL_WIDTH]) {
            // NL80211_ATTR_CENTER_FREQ1 attribute must be provided for bw 40 80 160
            // NL80211_ATTR_CENTER_FREQ2 attribute must be provided for bw 80P80
            switch (nla_get_u32(tb[NL80211_ATTR_CHANNEL_WIDTH])) {
            case NL80211_CHAN_WIDTH_20_NOHT:
            case NL80211_CHAN_WIDTH_20:
                info.bandwidth = 20;
                break;
            case NL80211_CHAN_WIDTH_40:
                info.bandwidth = 40;
                break;
            case NL80211_CHAN_WIDTH_80:
                info.bandwidth = 80;
                break;
            case NL80211_CHAN_WIDTH_80P80:
                if (tb[NL80211_ATTR_CENTER_FREQ2]) {
                    info.frequency_center2 = nla_get_u32(tb[NL80211_ATTR_CENTER_FREQ2]);
                }
                info.bandwidth = 160;
                break;
            case NL80211_CHAN_WIDTH_160:
                info.bandwidth = 160;
                break;
            default:
                info.bandwidth = 0;
                break;
            }
            if (info.bandwidth > 20 && tb[NL80211_ATTR_CENTER_FREQ1]) {
                info.frequency_center1 = nla_get_u32(tb[NL80211_ATTR_CENTER_FREQ1]);
            }
        }
    }
}

bool nl80211_client_impl::get_interface_info(const std::string &ifname, if_info &info)
{
    info = {};
    if (!m_socket) {
        std::cerr << "nl80211 socket is nullptr\n";
        return false;
    }

    int if_idx = if_nametoindex(ifname.c_str());
    if (0 == if_idx) {
        std::cerr << "Could not get index for interface '" << ifname << "'\n";
        return false;
    }

    return m_socket->send_receive_msg(
        NL80211_CMD_GET_INTERFACE, 0,
        [&](struct nl_msg *msg) -> bool {
            nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_idx);

            return true;
        },
        [&](struct nl_msg *msg) {
            struct nlattr *tb[NL80211_ATTR_MAX + 1];
            struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));

            // Parse the netlink message
            if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
                          NULL)) {
                std::cerr << "Failed to parse netlink message for NL80211_CMD_GET_INTERFACE\n";
                return;
            }

            if (tb[NL80211_ATTR_MAC]) {
                const uint8_t *data = static_cast<const uint8_t *>(nla_data(tb[NL80211_ATTR_MAC]));

                std::memcpy(info.mac.data(), data, 6);
            }

            if (tb[NL80211_ATTR_WIPHY]) {
                info.wiphy = nla_get_u32(tb[NL80211_ATTR_WIPHY]);
            }

            get_bandwidth_from_attr(tb, info);
        });
}

bool nl80211_client_impl::get_wiphy_bandwidth(if_info &info)
{
    return m_socket->send_receive_msg(
        NL80211_CMD_GET_INTERFACE, NLM_F_DUMP, [](struct nl_msg *msg) -> bool { return true; },
        [&](struct nl_msg *msg) {
            if (info.bandwidth) {
                return;
            }

            struct nlattr *tb[NL80211_ATTR_MAX + 1];
            struct genlmsghdr *gnlh = static_cast<struct genlmsghdr *>(nlmsg_data(nlmsg_hdr(msg)));

            // Parse the netlink message
            if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
                          NULL)) {
                std::cerr << "Failed to parse netlink message when getting wiphy bandwidth\n";
                return;
            }

            // Skip interfaces without a wiphy and non-AP interfaces:
            if (!tb[NL80211_ATTR_WIPHY] || !tb[NL80211_ATTR_IFTYPE] ||
                nla_get_u32(tb[NL80211_ATTR_IFTYPE]) != NL80211_IFTYPE_AP) {
                return;
            }

            uint32_t wiphy = nla_get_u32(tb[NL80211_ATTR_WIPHY]);

            if (wiphy != info.wiphy) {
                return;
            }

            get_bandwidth_from_attr(tb, info);
        });
}
