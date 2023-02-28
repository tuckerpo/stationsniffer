#pragma once
#include <functional>

struct nl_sock;
struct nl_msg;

class netlink_socket {
    int m_proto;

protected:
    struct nl_sock *m_nl_socket;

public:
    explicit netlink_socket(int proto);

    virtual ~netlink_socket();

    /**
     * @brief Connect to the kernel.
     * 
     * @return true on success, false otherwise.
     */
    virtual bool connect();

    /**
     * @brief Close the connection to the kernel.
     * 
     */
    virtual void close();

    /**
     * @brief Send an NL message to the kernel and get a response.
     * 
     * @param msg_create The message creation callback.
     * @param msg_handle The data callback, called on NL response.
     * @return true on success, false otherwise.
     */
    virtual bool send_receive_msg(std::function<bool(struct nl_msg *msg)> msg_create,
                                  std::function<void(struct nl_msg *msg)> msg_handle);
};