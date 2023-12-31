#include "netlink_socket.h"

#include <iostream>
#include <memory>
#include <netlink/msg.h>
#include <netlink/netlink.h>

netlink_socket::netlink_socket(int proto) : m_proto(proto) { m_nl_socket = nl_socket_alloc(); }

netlink_socket::~netlink_socket()
{
    if (m_nl_socket)
        nl_socket_free(m_nl_socket);
}

bool netlink_socket::connect()
{
    if (!m_nl_socket) {
        std::cerr << "Socket is nullptr\n";
        return false;
    }
    if (nl_connect(m_nl_socket, m_proto) != 0) {
        std::cerr << "Failed to connect to netlink socket with proto=" << m_proto << "\n";
        return false;
    }
    return true;
}

void netlink_socket::close()
{
    if (!m_nl_socket) {
        std::cerr << "Socket is nullptr\n";
        return;
    }
    nl_close(m_nl_socket);
}

bool netlink_socket::send_receive_msg(std::function<bool(struct nl_msg *msg)> msg_create,
                                      std::function<void(struct nl_msg *msg)> msg_handle)
{
    if (!m_nl_socket) {
        std::cerr << "Socket is nullptr\n";
        return false;
    }
    // The Netlink message to send
    std::unique_ptr<nl_msg, void (*)(nl_msg *)> nl_message(nlmsg_alloc(), nlmsg_free);
    if (!nl_message) {
        std::cerr << "Failed creating netlink message!\n";
        return false;
    }

    // The Netlink callback set
    std::unique_ptr<nl_cb, void (*)(nl_cb *)> nl_callback(nl_cb_alloc(NL_CB_DEFAULT), nl_cb_put);
    if (!nl_callback) {
        std::cerr << "Failed creating netlink callback!\n";
        return false;
    }

    // Termination flag for the loop that receives the response messages. Possible values are:
    // error == 1: initial value, request message has not be sent yet
    // error == 0: response has been successfully received
    // error < 0: some error occurred while receiving response
    // Final value is used to compute the result code of this method.
    int error = 1;

    // Create standard callbacks
    static auto nl_err_cb = [](struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg) -> int {
        int *error = (int *)arg;
        *error     = err->error;
        std::cerr << "Faield to process netlink message! Error: " << *error << "\n";
        return NL_STOP;
    };

    static auto nl_finish_cb = [](struct nl_msg *msg, void *arg) -> int {
        int *error = (int *)arg;
        *error     = 0;
        return NL_SKIP;
    };

    static auto nl_ack_cb = [](struct nl_msg *msg, void *arg) -> int {
        int *error = (int *)arg;
        *error     = 0;
        return NL_STOP;
    };

    // Response handler
    auto nl_handler_cb = [](struct nl_msg *msg, void *arg) -> int {
        // Delegate to the user's response message handling function
        auto msg_handle = static_cast<std::function<void(struct nl_msg * msg)> *>(arg);
        (*msg_handle)(msg);

        return NL_SKIP;
    };

    // Call the user's message create function
    if (!msg_create(nl_message.get())) {
        std::cerr << "User's netlink create function failed!\n";
        return false;
    }

    // Set the callbacks to handle the events fired by the Netlink library
    nl_cb_err(nl_callback.get(), NL_CB_CUSTOM, nl_err_cb, &error);
    nl_cb_set(nl_callback.get(), NL_CB_FINISH, NL_CB_CUSTOM, nl_finish_cb, &error);
    nl_cb_set(nl_callback.get(), NL_CB_ACK, NL_CB_CUSTOM, nl_ack_cb, &error);
    nl_cb_set(nl_callback.get(), NL_CB_VALID, NL_CB_CUSTOM, nl_handler_cb, &msg_handle);

    // Send the netlink message
    int rc = nl_send_auto_complete(m_nl_socket, nl_message.get());
    if (rc < 0) {
        std::cerr << "Failed to send netlink message! Error: " << rc << "\n";
        return false;
    }

    // Receive the response messages
    // Note that call to nl_recvmsgs() is blocking and loop terminates when one of these
    // conditions is met:
    // - nl_recvmsgs() fails (because internal call to nl_recv() in turn fails)
    // - One of the callback functions sets error to 0 (ok)
    // - One of the callback functions sets error to a value lower than 0 (error)
    // Loop is required just in case more than one message is received. Handling callback must
    // process them all.
    while (error > 0) {
        int rc = nl_recvmsgs(m_nl_socket, nl_callback.get());
        if (rc < 0) {
            std::cerr << "Failed to receive netlink messages! Error: " << rc << "\n";
            return false;
        }
    }

    // Return true on success and false otherwise
    return (0 == error);
}