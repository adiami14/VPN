#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <strings.h>
#include "../../include/network_utils.h"
#include "../../include/vpn.h"

#define SERVER "0.0.0.0"
int main()
{
    int max_fd = 0;
    vpn_serv_t *serv = Setup_server(5555, SERVER, "./log_server");
    fd_set master_set;
    struct sockaddr client_addr;
    socklen_t addrlen = sizeof(client_addr);

    SetRouteTable(AS_SERVER, NULL, serv->tun_name);

    FD_SET(serv->tun_fd, &master_set);
    FD_SET(serv->tcp_fd, &master_set);
    FD_SET(serv->udp_fd, &master_set);

    max_fd = MAX3(serv->log, serv->tun_fd, serv->udp_fd);
    while (1)
    {
        int ready_sockets = 0, i = 0;
        fd_set curr_set = master_set;

        ready_sockets = select(max_fd + 1, &curr_set, NULL, NULL, NULL);
        if (ready_sockets < 0)
        {
            break;
        }
        if (FD_ISSET(serv->tcp_fd, &curr_set))
        {
            printf("got tcp connection");
            VPN_Handle_NewConnection(serv);
        }
        if (FD_ISSET(serv->udp_fd, &curr_set))
        {
            char udp_buff[MTU] = {'0'};
            i = recvfrom(serv->udp_fd, udp_buff, MTU, 0, &client_addr, &addrlen);
            printf("server recived %d byte from udp\n", i);
            write(serv->tun_fd, udp_buff, i);
            printf("server wrote %s\n", udp_buff);
        }
        if (FD_ISSET(serv->tun_fd, &curr_set))
        {
            char tun_buff[MTU] = {'0'};
            i = read(serv->tun_fd, tun_buff, sizeof(tun_buff));
            printf("server read %d byte from tun\n", i);
            sendto(serv->udp_fd, tun_buff, i, 0, &client_addr, addrlen);
            printf("server sent %s\n", tun_buff);
        }
    }

    Destroy_server(serv, max_fd);

    return 0;
}