#ifndef VPN_H_CR4
#define VPN_H_CR4

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/select.h>
#include <stdio.h>
#include "../../cyber/include/network_utils.h"

#define SERVER_IP "192.168.5.36"
#define SERVER "0.0.0.0"
#define MTU 1400    
#define VPN_IP_NET "10.3.0."
#define SERVER_VPN_IP "10.3.0.1" 
#define INPUT "New Connection"
#define OUTPUT "ACK"
#define EXIT_MESSAGE "quit"
#define PORT 8080
#define LOG_PATH "./logger"

typedef struct vpn
{
    char *vpn_ip;
    int tun_fd;
    int udp_fd;
    int log;
    message_handle_t messege;
    struct sockaddr_in serv_addr;
    char tun_name[64];
}vpn_t;

typedef struct vpn_handler
{
    char *ip_pool[254];
    char *ip_clients[254];
    int tcp_fd;
}vpn_handler_t;

typedef enum set_as
{
    AS_CLIENT,
    AS_SERVER
}set_as_t;

char *VPN_Set_NewConnection(int port, const char *ip);
int VPN_Handle_NewConnection(vpn_handler_t *serv);

vpn_t *VPN_Setup();
int SetVNIC(vpn_t *serv);
void VPN_Destroy(vpn_t *serv, int max_fd);
void SetRouteTable(set_as_t type, const char *ip, const char *tun_name);
void Set_Input_Handling(vpn_t *serv, char *input_message, 
                        char *exit_message, char *output_message);

int Bind(struct sockaddr *addr, socklen_t *addrlen, const char *host, int port);
int Set_TCP_Listen();
void Destroy_handler(vpn_handler_t *serv);
vpn_handler_t *Set_Handler();
void Set_IpPool(char *ip_pool[]);
void Dealloc_Handler_Members(char *ip_clients[]);

#endif /* VPN_H_CR4 */