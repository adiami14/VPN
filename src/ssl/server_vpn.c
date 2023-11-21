#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <strings.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

#include "../../../include/network_utils.h"
#include "../../../include/vpn.h"
#include "../../../include/vpn_ssl.h"

#define SERVER "0.0.0.0"
#define CERT "cert.pem"
#define KEY "key.pem"

int main()
{
    int max_fd = 0, bre = 0, err_val = 0;
    fd_set master_set;
    BIO *bio;
    struct sockaddr_storage server_addr, client_addr;
    socklen_t server_addrlen = sizeof(server_addr), client_addrlen = sizeof(client_addr);
    ssl_handler_t *ssl_handler = SSL_Setup();
    vpn_handler_t *handler = Set_Handler();
    vpn_t *serv = VPN_Setup();
    if (serv == NULL)
    {
        exit(EXIT_FAILURE);
    }
    handler->tcp_fd = Set_TCP_Listen();
    if (handler->tcp_fd < 0)
    {
        exit(EXIT_FAILURE);
    }
    
    serv->tun_fd = SetVNIC(serv);
    if (serv->tun_fd < 0)
    {
        exit(EXIT_FAILURE);
    }
    
    SetRouteTable(AS_SERVER, SERVER_VPN_IP, serv->tun_name);
    serv->udp_fd = Bind((struct sockaddr *)&server_addr, &server_addrlen, SERVER, PORT);
    if (serv->udp_fd < 0)
    {
        exit(EXIT_FAILURE);
    }

    LoadCertificates(ssl_handler->ctx, CERT, KEY);
    ssl_handler->ssl = SSL_CTX_new(ssl_handler->method);
    SSL_set_fd(ssl_handler->ssl, serv->udp_fd);
    err_val = SSL_accept(ssl_handler->ssl);
    if (err_val <= 0)
    {
        SSL_get_error(ssl_handler->ssl, err_val);
        exit(EXIT_FAILURE);
    }
    printf("DTLS handshake successful\n");

    bio = BIO_new_dgram(serv->udp_fd, BIO_NOCLOSE);
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, NULL);

    SSL_set_bio(ssl_handler->ssl, bio, bio);
    SSL_set_options(ssl_handler->ssl, SSL_OP_COOKIE_EXCHANGE);
    
    
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
            if (sendto(serv->udp_fd, tun_buff, i, 0, (const struct sockaddr *)&server_addr, server_addrlen) < 0)
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
            i = recvfrom(serv->udp_fd, udp_buff, MTU, 0, (struct sockaddr *)&server_addr, &server_addrlen);
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