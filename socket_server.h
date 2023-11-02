#pragma once

// forward decl
struct pollfd;

#include "message_handler.h"
#include <netinet/in.h>
#include <string>
#include <sys/un.h>

/**
 * @brief Abstract base class of a socket server.
 * 
 * Handles incoming message requests (messages.h)
 * 
 * Subclasses should provide their own socket initialization implementations.
 */
class socket_server_abc {
protected:
    int m_server_fd;
    message_handler &m_message_handler;

public:
    explicit socket_server_abc(message_handler &);

    /**
     * @brief Subclass implementation of accept
     * 
     * @return int -1 on error, a client socket otherwise.
     */
    virtual int accept() = 0;

    /**
     * @brief Subclass implementation of creating a server socket.
     * 
     * @return true on success, false and m_server_fd set to -1 otherwise.
     */
    virtual bool socket_init() = 0;

    /**
     * @brief Begin serving.
     *
     * @param[in|out] keep_running If false, stop serving.
     *
     */
    virtual bool begin_serving(bool &keep_running);
};

/**
 * @brief Class to handle UDS socket server connections, reading, writing.
 */
class uds_socket_server : public socket_server_abc {
    std::string m_unix_socket_path;
    sockaddr_un m_remote;

public:
    /**
     * @brief Create a uds_socket_server object.
     *
     * @param unix_socket_path The path where this server will listen for connections & data.
     * @param msg_handler Broker for messages. Makes sense of raw data and calls callbacks.
     */
    explicit uds_socket_server(const std::string &unix_socket_path, message_handler &msg_handler);
    uds_socket_server() = default;
    virtual ~uds_socket_server();
    virtual bool socket_init() override;
    virtual int accept() override;

    /**
     * @brief Stops the UDS server.
     *
     * @return true on success, false otherwise.
     */
    bool stop_serving();
};

/**
 * @brief Class to handle TCP socket server connections, reading, writing.
 */
class socket_server_tcp : public socket_server_abc {
    int m_port;
    sockaddr_in m_remote;

public:
    explicit socket_server_tcp(int portno, message_handler &);
    virtual int accept() override;
    virtual bool socket_init() override;
};