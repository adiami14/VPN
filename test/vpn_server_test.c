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



int main()
{
    int max_fd = 0, bre = 0;
    fd_set master_set;
    struct sockaddr_storage client_addr;
    socklen_t client_addrlen = sizeof(client_addr);
    vpn_handler_t *handler = Set_Handler();
    vpn_t *serv = VPN_Setup();

    handler->tcp_fd = Set_TCP_Listen();
    
    serv->tun_fd = SetVNIC(serv);
    
    SetRouteTable(AS_SERVER, SERVER_VPN_IP, serv->tun_name);
    serv->udp_fd = Bind((struct sockaddr *)&client_addr, &client_addrlen, SERVER, PORT);
    if (serv->udp_fd < 0)
    {
        exit(EXIT_FAILURE);
    }

    FD_SET(serv->tun_fd, &master_set);
    FD_SET(serv->udp_fd, &master_set);
    FD_SET(handler->tcp_fd, &master_set);
    FD_SET(STDIN_FILENO, &master_set);

    max_fd = MAX3(serv->log, serv->tun_fd, serv->udp_fd);
    max_fd = MAX2(max_fd, handler->tcp_fd);
    while(bre == 0)
    {
        int i = 0;
        fd_set curr_set = master_set;
        
        if (select(max_fd + 1, &curr_set, NULL, NULL, NULL) < 0)
        {
            perror("select");
            return EXIT_FAILURE;
        }
        if (FD_ISSET(handler->tcp_fd, &curr_set))
        {
            printf("got tcp connection\n");
            if (VPN_Handle_NewConnection(handler) < 0)
            {
                printf("error handle new connection");
                break;
            }
        }
        if (FD_ISSET(serv->tun_fd, &curr_set))
        {
            char tun_buff[MTU] = {'0'};
            i = read(serv->tun_fd, tun_buff, sizeof(tun_buff));
            if (i < 0)
            {
                perror("read - server side");
                break;
            }
            printf("server read %d byte from tun\n", i);
            if (sendto(serv->udp_fd, tun_buff, i, 0, (const struct sockaddr *)&client_addr, client_addrlen) < 0)
            {
                perror("sendto server-side");
                break;
            }
            printf("server sent %s\n", tun_buff);
        }   
        if (FD_ISSET(serv->udp_fd, &curr_set))
        {
            char udp_buff[MTU] = {'0'};
            printf("recieved udp\n");
            i = recvfrom(serv->udp_fd, udp_buff, MTU, 0, (struct sockaddr *)&client_addr, &client_addrlen);
            if (i < 0)
            {
                perror("recvfrom - server side");
                break;
            }
            printf("server recived %d byte from udp --> %s\n", i, udp_buff);
            if (write(serv->tun_fd, udp_buff, i) < 0)
            {
                perror("write - server side");
                break;
            }
            printf("server wrote %s\n", udp_buff);
        }
        if (FD_ISSET(STDIN_FILENO, &curr_set))
        {
            char stdin_buff[MTU] = {'0'};
            i = read(STDIN_FILENO, stdin_buff, sizeof(stdin_buff));
            bre = InputHandler(stdin_buff, &serv->messege);
            if (strcmp(stdin_buff, "ifconfig") == 0)
            {
                system("ifconfig");
            }
        }
    }

    Destroy_handler(handler);
    VPN_Destroy(serv, max_fd);
    
    return 0;
}