#pragma once

// forward decl
struct pollfd;

#include "message_handler.h"
#include <string>

/**
 * @brief Class to handle UDS socket server connections, reading, writing.
 */
class socket_server {
    message_handler &m_message_handler;
    int m_server_fd;
    void add_to_poll_fdset(pollfd *pfds[], int new_fd, int &fd_count, int &poll_fd_size);
    void remove_from_poll_fdset(pollfd pfds[], int idx, int &fd_count);

public:
    /**
     * @brief Create a socket_server object.
     *
     * @param msg_handler Broker for messages. Makes sense of raw data and calls callbacks.
     */
    explicit socket_server(message_handler &msg_handler);
    socket_server() = default;
    virtual ~socket_server();
    /**
     * @brief Begin the socket server at path.
     *
     * @param path The path the server will listen on.
     * @param[in|out] keep_running If false, stop serving.
     *
     */
    bool begin_serving(const std::string &path, bool &keep_running);

    /**
     * @brief Stops the UDS server.
     *
     * @return true on success, false otherwise.
     */
    bool stop_serving();
};
