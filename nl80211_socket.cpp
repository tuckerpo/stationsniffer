#include "nl80211_socket.h"

#include <iostream>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>

static constexpr int netlink_buf_size = 8192;

nl80211_socket::nl80211_socket(int proto) : netlink_socket(proto) {}

bool nl80211_socket::connect()
{
    bool result = netlink_socket::connect();

    // Increase the socket's internal buffer size
    if (result) {
        int rc = nl_socket_set_buffer_size(m_nl_socket, netlink_buf_size, netlink_buf_size);
        if (rc < 0) {
            std::cerr << "Failed to set buffer size! Error: " << rc << "\n";
        }
    }

    // Resolve the generic nl80211 family id
    if (result) {
        const char *family_name = "nl80211";

        m_family_id = genl_ctrl_resolve(m_nl_socket, family_name);
        if (0 > m_family_id) {
            std::cerr << "'" << family_name << "' family not found!\n";
            result = false;

            close();
        }
    }

    return result;
}

bool nl80211_socket::send_receive_msg(int command, int flags,
                                      std::function<bool(struct nl_msg *msg)> msg_create,
                                      std::function<void(struct nl_msg *msg)> msg_handle)
{
    return netlink_socket::send_receive_msg(
        [&](struct nl_msg *msg) -> bool {
            // Initialize the netlink message
            if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, m_family_id, 0, flags, command, 0)) {
                std::cerr << "Failed initializing the netlink message!\n";
                return false;
            }

            // Call the user's message create function
            return msg_create(msg);
        },
        msg_handle);
}
