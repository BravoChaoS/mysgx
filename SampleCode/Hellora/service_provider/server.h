//
// Created by jojjiw on 2021/3/8.
//

#ifndef HELLORA_SERVER_H
#define HELLORA_SERVER_H


#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>


class server {
private:
    int listen_fd = -1;
public:
    int init();

    int start_listen() const;
};


#endif //HELLORA_SERVER_H
