//
// Created by jojjiw on 2021/3/8.
//

#include "server.h"

int server::init() {

    std::cout << "Init server" << std::endl;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        std::cout << "ERROR: create socket failed" << std::endl;
        return -1;
    }

    int res = 0;
    sockaddr_in addr{AF_INET, 8000, INADDR_ANY};
    res = bind(listen_fd, (struct sockaddr *) &addr, sizeof(addr));
    if (res < 0) {
        std::cout << "ERROR: bind failed" << std::endl;
        return -1;
    }
    std::cout << "init success" << std::endl;
    return 0;

}

int server::start_listen() const {
    if (listen_fd < 0) {
        std::cout << "ERROR: no such socket" << std::endl;
        return -1;
    }
    int res = listen(listen_fd, 5);
    if (res < 0) {
        std::cout << "ERROR: listen failed" << std::endl;
        return -1;
    }
    std::cout << "listen success" << std::endl;
    return 0;
}
