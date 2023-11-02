#include "socket_server.h"
#include <arpa/inet.h>
#include <cstring>
#include <errno.h>
#include <iostream>
#include <netinet/in.h>
#include <pcap.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

socket_server_abc::socket_server_abc(message_handler &msg_handler)
    : m_server_fd(-1), m_message_handler(msg_handler)
{
}

bool socket_server_abc::begin_serving(bool &keep_running)
{
    if (!socket_init())
        return false;
    std::vector<pollfd> pollfd_vector;
    // Add the server pollfd to the set.
    pollfd_vector.push_back({m_server_fd, POLLIN, 0});
    while (keep_running) {
        int poll_count = poll(pollfd_vector.data(), (nfds_t)pollfd_vector.size(), 1000);
        if (poll_count == -1) {
            perror("poll");
        }
        std::vector<int> clients_to_be_removed;
        std::vector<int> new_clients{};
        for (auto &pfd : pollfd_vector) {
            if (pfd.revents & POLLIN) {
                if (pfd.fd == m_server_fd) {
                    // new connection.
                    // mark new client for insertion to client list outside of
                    // current iteration (push_back potentially invalidates the
                    // begin or end iterators if reallocation occurs)
                    int new_conn_fd = accept();
                    if (new_conn_fd == -1) {
                        perror("accept");
                    } else {
                        new_clients.push_back(new_conn_fd);
                        std::cout << "New connection! fd=" << new_conn_fd << std::endl;
                    }
                } else {
                    char rxbuf[256];
                    int nbytes    = recv(pfd.fd, rxbuf, sizeof(rxbuf), 0);
                    int sender_fd = pfd.fd;
                    if (nbytes <= 0) {
                        if (nbytes == 0) {
                            std::cerr << "Client hung up on fd: " << sender_fd << std::endl;
                        } else {
                            // TODO check errors better (EAGAIN, EWOULDBLOCK etc);
                            perror("recv");
                        }
                        // Mark for removal.
                        clients_to_be_removed.push_back(pfd.fd);
                    } else {
                        // good data.
                        std::vector<uint8_t> payload;
                        payload.reserve(sizeof(rxbuf));
                        std::copy(rxbuf, rxbuf + sizeof(rxbuf), std::back_inserter(payload));
                        m_message_handler.post_data(payload, pfd.fd);
                    }
                }
            }
        }
        if (!new_clients.empty()) {
            // Add new clients to the poll fd set
            for (const int &fd : new_clients) {
                pollfd_vector.push_back({fd, POLLIN, 0});
            }
            new_clients.clear();
        }
        // Walk dead clients and remove them from the poll set.
        for (const auto &dead_client_fd : clients_to_be_removed) {
            auto pollfd_entry_to_remove = std::find_if(pollfd_vector.begin(), pollfd_vector.end(),
                                                       [&dead_client_fd](pollfd &pollfd_entry) {
                                                           return pollfd_entry.fd == dead_client_fd;
                                                       });
            if (pollfd_entry_to_remove != pollfd_vector.end()) {
                close(pollfd_entry_to_remove->fd);
                std::cout << "Removing pollfd entry for dead client, fd="
                          << pollfd_entry_to_remove->fd << std::endl;
                pollfd_vector.erase(pollfd_entry_to_remove);
            }
        }
    }
    return true;
}

uds_socket_server::uds_socket_server(const std::string &unix_socket_path,
                                     message_handler &msg_handler)
    : socket_server_abc(msg_handler), m_unix_socket_path(unix_socket_path)
{
    m_remote = {0};
}

uds_socket_server::~uds_socket_server() { stop_serving(); }

bool uds_socket_server::socket_init()
{
    static constexpr int listen_backlog = 10;

    sockaddr_un local = {0};
    m_server_fd       = socket(AF_UNIX, SOCK_STREAM, 0);
    if (m_server_fd == -1) {
        perror("socket");
        return false;
    }
    local.sun_family = AF_UNIX;
    std::strncpy(local.sun_path, m_unix_socket_path.c_str(), m_unix_socket_path.length());
    unlink(m_unix_socket_path.c_str());
    if (bind(m_server_fd, (sockaddr *)&local, sizeof(local)) < 0) {
        perror("bind");
        return false;
    }
    if (listen(m_server_fd, listen_backlog) < 0) {
        perror("listen");
        return false;
    }
    std::cout << "UDS server listening at " << m_unix_socket_path << std::endl;
    return m_server_fd != -1;
}

int uds_socket_server::accept()
{
    socklen_t sock_len;
    return ::accept(m_server_fd, (sockaddr *)&m_remote, &sock_len);
}

bool uds_socket_server::stop_serving()
{
    if (m_server_fd != -1)
        close(m_server_fd);
    return true;
}

socket_server_tcp::socket_server_tcp(int port, message_handler &msg_handler)
    : socket_server_abc(msg_handler), m_port(port)
{
    m_remote = {0};
}

int socket_server_tcp::accept()
{
    socklen_t sock_len;
    return ::accept(m_server_fd, (struct sockaddr *)&m_remote, &sock_len);
}

bool socket_server_tcp::socket_init()
{
    static constexpr int listen_backlog = 10;

    sockaddr_in local = {0};
    m_server_fd       = socket(AF_INET, SOCK_STREAM, 0);
    if (m_server_fd == -1) {
        perror("socket");
        return false;
    }
    local.sin_family      = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port        = m_port;
    if (bind(m_server_fd, (sockaddr *)&local, sizeof(local)) < 0) {
        perror("bind");
        return false;
    }
    if (listen(m_server_fd, listen_backlog) < 0) {
        perror("listen");
        return false;
    }
    std::cout << "TCP server listening on port " << m_port << std::endl;
    return m_server_fd != -1;
}
