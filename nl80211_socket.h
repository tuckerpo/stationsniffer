#pragma once

#include "netlink_socket.h"

class nl80211_socket : public netlink_socket {
    int m_family_id = 0;

public:
    explicit nl80211_socket(int proto);
    virtual bool connect() override;

    virtual bool send_receive_msg_wrapper(int command, int flags,
                                          std::function<bool(struct nl_msg *msg)> msg_create,
                                          std::function<void(struct nl_msg *msg)> msg_handle);
};