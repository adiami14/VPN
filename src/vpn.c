#define _POSIX_C_SOURCE 200112L
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <sys/types.h> /* open, fnctl */
#include <sys/stat.h>  /* open, fnctl */
#include <fcntl.h>     /* open, fnctl */
#include <stdlib.h>    /* malloc exit */
#include <unistd.h>    /* STDIN_FILENO */
#include <stdio.h>     /* open, print */
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h> /* TUN configuration */
#include <strings.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <signal.h>

#include "../../include/vpn_ssl.h"
#include "../../../cyber/include/network_utils.h"
#include "../../../cyber/include/vpn.h"

static void Zero_arr(char *arr[], size_t size);

static void Zero_arr(char *arr[], size_t size)
{
    size_t i = 0;
    for (i = 0; i < size; --i)
    {
        arr[i] = NULL;
    }
    return;
}

void Set_IpPool(char *ip_pool[])
{
    size_t i = 0;
    char di[4];
    for (i = 0; i < 253; ++i)
    {
        ip_pool[i] = malloc(INET_ADDRSTRLEN);
        if (ip_pool[i] == NULL)
        {
            perror("malloc ip_pool");
            exit(EXIT_FAILURE);
        }
        strcpy(ip_pool[i], VPN_IP_NET);
        sprintf(di, "%ld", (i + 2));
        strcat(ip_pool[i], di);
    }

    return;
}

void Dealloc_Handler_Members(char *ip_clients[])
{
    size_t i = 0;
    for (i = 0; i < 253; ++i)
    {
        if (ip_clients[i] != NULL)
        {
            free(ip_clients[i]);
        }
    }
    return;
}

vpn_handler_t *Set_Handler()
{
    vpn_handler_t *handler = (vpn_handler_t *)malloc(sizeof(vpn_handler_t));
    if (handler == NULL)
    {
        perror("malloc handler");
        exit(EXIT_FAILURE);
    }
    Set_IpPool(handler->ip_pool);
    Zero_arr(handler->ip_clients, 254);

    return handler;
}

void Destroy_handler(vpn_handler_t *serv)
{
    Dealloc_Handler_Members(serv->ip_clients);
    Dealloc_Handler_Members(serv->ip_pool);
    free(serv);
}

int SetVNIC(vpn_t *serv)
{
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
    {
        perror("open");
        exit(EXIT_FAILURE);
    }

    bzero(&ifr, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if ((ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0)
    {
        perror("ioctl[TUNSETIFF]");
        close(fd);
        exit(EXIT_FAILURE);
    }
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
    {
        perror("SetVNIC fcntl");
        close(fd);
        exit(EXIT_FAILURE);
    }
    strcpy(serv->tun_name, ifr.ifr_name);
    printf("tun set to name: %s\n", serv->tun_name);
    return fd;
}

void Restart_Routing()
{
    system("sudo ip route flush table main");
    system("sudo systemctl restart NetworkManager");
    system("sudo iptables -t nat -F");
    printf("\n\n");
    system("route -n");
    printf("\n\n");
    return;
}

void SetRouteTable(set_as_t type, const char *ip, const char *tun_name)
{
    int err_val = 0;
    char *dev = GetDefaultGW_Interface();
    char cmd[1024] = {0};
    
    Restart_Routing();

    err_val = system("sysctl -w net.ipv4.ip_forward=1");
    ErrorCheck("system\n", err_val);
    sprintf(cmd, "ifconfig %s %s/24 mtu %d up", tun_name, ip, MTU);
    printf("%s\n", cmd);
    system(cmd);
    bzero(cmd, 1024);

    if (type == AS_CLIENT)
    {
        sprintf(cmd, "ip route add %s dev %s", SERVER_IP, dev);
        printf("%s\n", cmd);
        system(cmd);
        bzero(cmd, 1024);
        sprintf(cmd, "ip route add 0.0.0.0/0 dev %s", tun_name);
        printf("%s\n", cmd);
        system(cmd);
        return;
    }
    else
    {
        system("iptables -t nat -A POSTROUTING -j MASQUERADE");
        return;
    }
    system("route -n");
}

vpn_t *VPN_Setup()
{
    vpn_t *serv = (vpn_t *)malloc(sizeof(vpn_t));
    if (serv == NULL)
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    serv->log = SetLogger(LOG_PATH);
    if (serv->log < 0)
    {
        VPN_Destroy(serv, serv->log + 1);
        exit(EXIT_FAILURE);
    }

    if (fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK))
    {
        VPN_Destroy(serv, MAX2(serv->log, STDIN_FILENO) + 1);
        exit(EXIT_FAILURE);
    }
    Set_Input_Handling(serv, INPUT, EXIT_MESSAGE, OUTPUT);
    return serv;
}

void VPN_Destroy(vpn_t *serv, int max_fd)
{
    int i = 0;
    for (i = 3; i <= max_fd + 1; ++i)
    {
        printf("for fd --> %d\n", i);
        if (fcntl(i, F_GETFL) != -1 && errno != EBADF)
        {
            printf("closing --> %d\n", i);
            errno = 0;
            close(i);
        }
    }
    free(serv);
    Restart_Routing();
    return;
}

void Set_Input_Handling(vpn_t *serv, char *input_message, char *exit_message, char *output_message)
{
    serv->messege.exit_message = exit_message;
    serv->messege.input_message = input_message;
    serv->messege.output_message = output_message;

    return;
}


int Set_TCP_Listen()
{
    int reuse = 1;
    struct sockaddr_in servaddr;
    int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd < 0)
    {
        perror("tcp socket");
        return -1;
    }
    if (setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
    {
        perror("setsockopt");
        return -1;
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);
   
    if ((bind(tcp_fd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) {
        printf("socket bind failed...\n");
        exit(0);
    }

    if (fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK))
    {
        perror("TCP socket: fcntl");
        return -1;
    }
    if (listen(tcp_fd, SOMAXCONN) < 0)
    {
        perror("listen");
        return -1;
    }
    return tcp_fd;
    
}

int VPN_Handle_NewConnection(vpn_handler_t *serv)
{
    size_t i = 0;
    char ipAddress[INET_ADDRSTRLEN];
    size_t addr_size = sizeof(struct sockaddr);
    struct sockaddr_in client_address;
    int new_socket = 0;

    memset(&client_address, '0', sizeof(client_address));
    new_socket = accept(serv->tcp_fd, (struct sockaddr *)&client_address, (socklen_t *)&addr_size);
    if (new_socket < 0)
    {
        perror("accept");
        return -1;
    }
    inet_ntop(AF_INET, &(client_address.sin_addr), ipAddress, INET_ADDRSTRLEN);
    printf("accept new connection");
    while (serv->ip_clients[i] != NULL)
    {
        if (i > 254)
        {
            return -1;
        }
        ++i;
    }

    serv->ip_clients[i] = malloc(sizeof(char *));
    if (serv->ip_clients[i] == NULL)
    {
        return -1;
    }
    strcpy(serv->ip_clients[i], ipAddress);
    printf("New Client connection: %s\n", ipAddress);

    if (send(new_socket, serv->ip_pool[i], INET_ADDRSTRLEN, 0) < 0)
    {
        return -1;
    }
    close(new_socket);

    return 0;
}

char *VPN_Set_NewConnection(int port, const char *ip)
{
    int tcp_fd;
    int status = 0;
    char buff[1024] = {'\0'};
    char *new_addr = NULL;
    struct sockaddr_in serv_addr;

    tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd < 0)
    {
        perror("socket");
        return NULL;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &(serv_addr.sin_addr)) <= 0)
    {
        perror("inet_pton");
        return NULL;
    }

    status = connect(tcp_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (status < 0)
    {
        perror("connect");
        return NULL;
    }

    if (send(tcp_fd, INPUT, strlen(INPUT), 0) < 0)
    {
        perror("send");
        return NULL;
    }

    printf("send\n");

    if (recv(tcp_fd, buff, INET_ADDRSTRLEN, 0) < 0)
    {
        perror("recv");
        return NULL;
    }
    close(tcp_fd);
    printf("received new ip %s\n", buff);

    new_addr = (char *)malloc(INET_ADDRSTRLEN);
    if (NULL == new_addr)
    {
        perror("malloc");
        return NULL;
    }

    strcpy(new_addr, buff);

    return new_addr;
}


int Bind(struct sockaddr *addr, socklen_t *addrlen, const char *host, int port)
{
    struct addrinfo hints;
    struct addrinfo *result;
    int sock, flags;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    if (0 != getaddrinfo(host, NULL, &hints, &result))
    {
        perror("getaddrinfo error");
        return -1;
    }
    if (result->ai_family == AF_INET)
    {
        ((struct sockaddr_in *)result->ai_addr)->sin_port = htons(port);
    }
    else if (result->ai_family == AF_INET6)
    {
        ((struct sockaddr_in6 *)result->ai_addr)->sin6_port = htons(port);
    }
    else
    {
        fprintf(stderr, "unknown ai_family %d", result->ai_family);
        freeaddrinfo(result);
        return -1;
    }

    memcpy(addr, result->ai_addr, result->ai_addrlen);
    *addrlen = result->ai_addrlen;

    if (-1 == (sock = socket(result->ai_family, SOCK_DGRAM, IPPROTO_UDP)))
    {
        perror("UDP socket");
        freeaddrinfo(result);
        return -1;
    }

    if (strcmp(host, "0.0.0.0") == 0)
    {
        printf("bind Server socket\n");
        if (0 != bind(sock, result->ai_addr, result->ai_addrlen))
        {
            perror("Cannot bind");
            close(sock);
            freeaddrinfo(result);
            return -1;
        }
    }

    freeaddrinfo(result);

    flags = fcntl(sock, F_GETFL, 0);
    if (flags != -1)
    {
        if (-1 != fcntl(sock, F_SETFL, flags | O_NONBLOCK))
            return sock;
    }
    perror("fcntl error");

    close(sock);
    return -1;
}