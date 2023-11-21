#define _POSIX_C_SOURCE 2
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/stat.h> /* open, fnctl */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <pthread.h>
#include <unistd.h> /* for getopt	*/
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <resolv.h>      /*server to find out the runner's IP address*/
#include <netdb.h>       /*definitions for network database operations */
#include <openssl/ssl.h> /*using openssl function's and certificates and configuring them*/
#include <openssl/err.h> /* helps in finding out openssl errors*/
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#include <pthread.h>

#include "../../include/vpn_ssl.h"
#include "../../include/vpn.h"
#include "../../../cyber/include/network_utils.h"

#define BUFFER_SIZE (1024)
#define M (4)

typedef struct pass_info
{
    struct sockaddr_storage server_addr;
    struct sockaddr_storage client_addr;
    SSL *ssl;
    char *ip;
} pass_info_t;

static int Set_Listening_Udp(struct sockaddr_in *server_addr, int port);
static int SetNewSocket(struct pass_info *pinfo, int type);

void *connection_handle(void *info);

void StartServer(int port)
{
    int fd, i = 0;
    struct sockaddr_in server_addr, client_addr;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *bio = NULL;
    struct timeval timeout;
    struct pass_info *info;
    char *ip_pool[254];
    /* pthread_t id[M]; */

    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    SSL_Confid_Server(&ctx);

    fd = Set_Listening_Udp(&server_addr, port);

    Set_IpPool(ip_pool);
    while (1)
    {
        memset(&client_addr, 0, sizeof(struct sockaddr_in));

        /* Create BIO */
        bio = BIO_new_dgram(fd, BIO_NOCLOSE);

        /* Set and activate timeouts */
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        ssl = SSL_new(ctx);

        SSL_set_bio(ssl, bio, bio);
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

        while (DTLSv1_listen(ssl, (BIO_ADDR *)&client_addr) <= 0)
            ;

        /* printf("DTLSv1_listen return --> %d, creating new thread!\n", res); */
        if (memcmp(&info->client_addr, &client_addr, sizeof(client_addr)) != 0)
        {

            info = (struct pass_info *)malloc(sizeof(struct pass_info));
            memcpy(&info->server_addr, &server_addr, sizeof(struct sockaddr_in));
            memcpy(&info->client_addr, &client_addr, sizeof(struct sockaddr_in));
            info->ssl = ssl;
            info->ip = ip_pool[i];
            if (NULL == connection_handle(info))
            {
                break;
            }
            /* if (pthread_create(&id[i], NULL, &connection_handle, info) != 0)
            {
                perror("Pthread_create: ");
            }
            pthread_detach(id[i]);
            ++i; */
        }
    }
    Restart_Routing();
    Dealloc_Handler_Members(ip_pool);
    return;
}

void *connection_handle(void *info)
{
    ssize_t len;
    fd_set master_set;
    char buf[BUFFER_SIZE];
    struct pass_info *pinfo = (struct pass_info *)info;
    SSL *ssl = pinfo->ssl;
    int max_fd = 0, bre = 0, ret;
    struct timeval timeout;
    vpn_t *serv = VPN_Setup();

    serv->tun_fd = SetVNIC(serv);
    SetRouteTable(AS_SERVER, SERVER_VPN_IP, serv->tun_name);
    /* SetRouteTable(AS_SERVER, SERVER_VPN_IP, serv->tun_name); */

    serv->udp_fd = SetNewSocket(pinfo, SOCK_DGRAM);
    if (serv->udp_fd < 0)
    {
        printf("SetNewSocket failed\n");
        SSL_shutdown(ssl);
        free(info);
        SSL_free(ssl);
        free(serv);
        return NULL;
    }
    /* Set new fd and set BIO to connected */
    BIO_set_fd(SSL_get_rbio(ssl), serv->udp_fd, BIO_NOCLOSE);
    BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &pinfo->client_addr);

    /* Finish handshake */
    do
    {
        ret = SSL_accept(ssl);
    } while (ret == 0);
    if (ret < 0)
    {
        perror("SSL_accept");
        printf("%s\n", ERR_error_string(ERR_get_error(), buf));
        handle_socket_error();
        return NULL;
    }

    /* Set and activate timeouts */
    timeout.tv_sec = 60;
    timeout.tv_usec = 0;
    BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    FD_SET(serv->tun_fd, &master_set);
    FD_SET(serv->udp_fd, &master_set);

    max_fd = MAX3(serv->log, serv->tun_fd, serv->udp_fd);
    while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) && bre == 0)
    {
        int i = 0;
        fd_set curr_set = master_set;

        if (select(max_fd + 1, &curr_set, NULL, NULL, NULL) < 0)
        {
            perror("select");
        }
        if (FD_ISSET(serv->udp_fd, &curr_set))
        {
            char udp_buff[MTU] = {'0'};
            printf("recieved udp\n");
            len = SRead(ssl, udp_buff, BUFFER_SIZE);

            if (write(serv->tun_fd, udp_buff, len) < 0)
            {
                perror("write - server side");
                break;
            }
            printf("server wrote %s\n", udp_buff);
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
            SWrite(ssl, tun_buff, i);
        }
    }

    SSL_shutdown(ssl);

    close(serv->udp_fd);
    free(info);
    SSL_free(ssl);
    free(serv);
    return NULL;
}

void start_client(char *remote_address, int port)
{
    int i = 0, max_fd = 0;
    struct sockaddr_in remote_addr, local_addr;
    char buf[BUFFER_SIZE];
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    fd_set master_set;
    vpn_t *serv = VPN_Setup();

    memset((void *)&remote_addr, 0, sizeof(struct sockaddr_in));
    memset((void *)&local_addr, 0, sizeof(struct sockaddr_in));

    if (1 == inet_pton(AF_INET, remote_address, &remote_addr.sin_addr))
    {
        remote_addr.sin_family = AF_INET;
        remote_addr.sin_port = htons(port);
    }
    else
    {
        perror("inet_pton - client");
        return;
    }

    serv->udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (serv->udp_fd < 0)
    {
        perror("socket");
        handle_socket_error();
        exit(EXIT_FAILURE);
    }

    SSL_load_error_strings();

    ctx = SSL_CTX_new(DTLS_client_method());
    /* SSL_CTX_set_cipher_list(ctx, "eNULL:!MD5"); */

    LoadCertificates(ctx, CERT_CLIENT, KEY_CLIENT);

    SSL_CTX_set_verify_depth(ctx, 2);
    SSL_CTX_set_read_ahead(ctx, 1);

    ssl = SSL_new(ctx);

    /* Create BIO, connect and set to already connected */
    bio = BIO_new_dgram(serv->udp_fd, BIO_CLOSE);
    if (connect(serv->udp_fd, (struct sockaddr *)&remote_addr, sizeof(struct sockaddr_in)) < 0)
    {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &remote_addr);

    SSL_set_bio(ssl, bio, bio);

    while (SConnect(ssl) <= 0)
    {
        ++i;
        if (i % 100 == 0)
        {
            printf("SCONNECT NOT READY YET\n");
        }
    }
    printf("connected!!!!!!!\n");
    /* Set and activate timeouts */
    /* timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout); */

    serv->vpn_ip = "10.3.0.5";
    serv->tun_fd = SetVNIC(serv);
    SetRouteTable(AS_CLIENT, serv->vpn_ip, serv->tun_name);
    FD_SET(serv->tun_fd, &master_set);
    FD_SET(serv->udp_fd, &master_set);
    FD_SET(STDIN_FILENO, &master_set);
    max_fd = MAX3(serv->log, serv->tun_fd, serv->udp_fd);
    while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN))
    {
        int i = 0;
        fd_set curr_set = master_set;

        if (select(max_fd + 1, &curr_set, NULL, NULL, NULL) < 0)
        {
            perror("select");
        }
        if (FD_ISSET(serv->tun_fd, &curr_set))
        {
            char tun_buff[MTU] = {'0'};
            i = read(serv->tun_fd, tun_buff, sizeof(tun_buff));
            if (i < 0)
            {
                perror("read - client side");
                break;
            }
            printf("client read %d byte from tun\n", i);
            i = SWrite(ssl, tun_buff, i);
            printf("client wrote %d byte from tun\n", i);
        }
        if (FD_ISSET(serv->udp_fd, &curr_set))
        {
            char udp_buff[MTU] = {'0'};
            i = SRead(ssl, udp_buff, sizeof(buf));
            printf("server recived %d byte from udp\n", i);
            i = write(serv->tun_fd, udp_buff, i);
            if (i < 0)
            {
                perror("write - client side");
                break;
            }
            printf("server wrote %d bytes\n", i);
        }
        if (FD_ISSET(STDIN_FILENO, &curr_set))
        {
            char stdin_buff[MTU] = {'0'};
            if (read(STDIN_FILENO, stdin_buff, sizeof(stdin_buff)) < 0)
            {
                perror("client read - stdin");
                break;
            }
            if (InputHandler(stdin_buff, &serv->messege) < 0)
            {
                SSL_shutdown(ssl);
            }
            if (strcmp(stdin_buff, "ifconfig") == 0)
            {
                system("ifconfig");
            }
        }
    }

    close(serv->udp_fd);
    printf("Connection closed.\n");
}
int main(int argc, char *argv[])
{
    (void)argc;
    if (strcmp(argv[1], "-server") == 0)
    {
        printf("start as server\n");
        StartServer(PORT);
    }
    else
    {
        printf("start as client\n");
        start_client("192.168.5.36", PORT);
    }

    return 0;
}

static int SetNewSocket(struct pass_info *pinfo, int type)
{
    int on = 1;
    int fd = socket(AF_INET, type, 0);
    if (fd < 0)
    {
        perror("socket");
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, (socklen_t)sizeof(on)) < 0)
    {
        perror("connection handler setsockopt");
        close(fd);
        return -1;
    }
#if defined(SO_REUSEPORT) && !defined(__linux__)
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void *)&on, (socklen_t)sizeof(on));
#endif
    if (bind(fd, (const struct sockaddr *)&pinfo->server_addr, sizeof(struct sockaddr_in)) < 0)
    {
        perror("second bind in connection handler");
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&pinfo->client_addr, sizeof(struct sockaddr_in)) < 0)
    {
        perror("second connect in connection handler");
        close(fd);
        return -1;
    }

    return fd;
}

static int Set_Listening_Udp(struct sockaddr_in *server_addr, int port)
{

    int fd, on = 0;
    memset(server_addr, 0, sizeof(struct sockaddr_in));

    server_addr->sin_addr.s_addr = INADDR_ANY;
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(port);

    fd = socket(server_addr->sin_family, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        perror("socket");
        exit(-1);
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, (socklen_t)sizeof(on)) < 0)
    {
        perror("server setsockopt 1");
    }
#if defined(SO_REUSEPORT)
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void *)&on, (socklen_t)sizeof(on));
#endif
    if (bind(fd, (const struct sockaddr *)server_addr, sizeof(struct sockaddr_in)) < 0)
    {
        perror("server bind 1");
    }

    return fd;
}