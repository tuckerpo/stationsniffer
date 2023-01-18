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

socket_server::socket_server(message_handler &msg_handler)
    : m_message_handler(msg_handler), m_server_fd(-1)
{
}

socket_server::~socket_server() { stop_serving(); }

bool socket_server::begin_serving(const std::string &path, bool &keep_running)
{
    static constexpr int listen_backlog = 10;

    int fd_size     = 5;
    pollfd *pfds    = (pollfd *)malloc(sizeof(pollfd *) * fd_size);
    const auto bail = [&pfds]() {
        free(pfds);
        return false;
    };

    sockaddr_un remote = {0};
    sockaddr_un local  = {0};
    m_server_fd        = socket(AF_UNIX, SOCK_STREAM, 0);
    if (m_server_fd == -1) {
        perror("socket");
        return false;
    }
    local.sun_family = AF_UNIX;
    std::strncpy(local.sun_path, path.c_str(), path.length());
    unlink(path.c_str());
    if (bind(m_server_fd, (sockaddr *)&local, sizeof(local)) < 0) {
        perror("bind");
        bail();
    }
    if (listen(m_server_fd, listen_backlog) < 0) {
        perror("listen");
        bail();
    }

    pfds[0].fd     = m_server_fd;
    pfds[0].events = POLLIN;
    int fd_count   = 1; // m_server_fd
    while (keep_running) {
        int poll_count = poll(pfds, fd_count, 1000);
        if (poll_count == -1) {
            perror("poll");
        }
        for (int i = 0; i < fd_count; i++) {
            if (pfds[i].revents & POLLIN) {
                if (pfds[i].fd == m_server_fd) {
                    // new connection.
                    unsigned sock_len = 0;
                    int new_conn_fd   = accept(m_server_fd, (sockaddr *)&remote, &sock_len);
                    if (new_conn_fd == -1) {
                        perror("accept");
                    } else {
                        add_to_poll_fdset(&pfds, new_conn_fd, fd_count, fd_size);
                        std::cout << "New connection!" << std::endl;
                    }
                } else {
                    char rxbuf[256];
                    int nbytes    = recv(pfds[i].fd, rxbuf, sizeof(rxbuf), 0);
                    int sender_fd = pfds[i].fd;
                    if (nbytes <= 0) {
                        if (nbytes == 0) {
                            std::cerr << "Client hung up on fd: " << sender_fd << std::endl;
                        } else {
                            // TODO check errors better (EAGAIN, EWOULDBLOCK etc);
                            perror("recv");
                        }
                        // error, remove from poll set
                        close(pfds[i].fd);
                        remove_from_poll_fdset(pfds, i, fd_count);
                    } else {
                        // good data.
                        std::vector<uint8_t> payload;
                        payload.reserve(sizeof(rxbuf));
                        std::copy(rxbuf, rxbuf + sizeof(rxbuf), std::back_inserter(payload));
                        m_message_handler.post_data(payload, pfds[i].fd);
                    }
                }
            }
        }
    }
    free(pfds);
    return stop_serving();
}

bool socket_server::stop_serving()
{
    if (m_server_fd != -1)
        close(m_server_fd);
    return true;
}

void socket_server::add_to_poll_fdset(pollfd *pfds[], int new_fd, int &fd_count, int &poll_fd_size)
{
    if (fd_count == poll_fd_size) {
        poll_fd_size *= 2;
        *pfds = (pollfd *)realloc(*pfds, sizeof(**pfds) * (poll_fd_size));
    }
    (*pfds)[fd_count].fd     = new_fd;
    (*pfds)[fd_count].events = POLLIN;
    fd_count++;
}

void socket_server::remove_from_poll_fdset(pollfd pfds[], int idx, int &fd_count)
{
    pfds[idx] = pfds[fd_count - 1];
    fd_count--;
}
