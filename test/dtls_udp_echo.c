#define _POSIX_C_SOURCE 2
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <pthread.h>
#include <unistd.h> /* for getopt	*/

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#include "../../include/vpn_ssl.h"
#include "../../include/vpn.h"

#define BUFFER_SIZE (1024)
#define COOKIE_SECRET_LENGTH 16
#define ZERO (0)

typedef struct pass_info
{
	struct sockaddr_storage server_addr;
	struct sockaddr_storage client_addr;
	SSL *ssl;
} pass_info_t;

void start_server(int port);
void start_client(char *remote_address, int port);

void connection_handle(void *info)
{
	ssize_t len;
	char buf[BUFFER_SIZE];
	struct pass_info *pinfo = (struct pass_info *)info;
	SSL *ssl = pinfo->ssl;
	int fd, reading = 0, ret;
	const int on = 1;
	struct timeval timeout;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));

	if (bind(fd, (const struct sockaddr *)&pinfo->server_addr, sizeof(struct sockaddr_in)) < 0)
	{
		perror("second bind in connection handler");
		/* exit(EXIT_FAILURE); */
	}
	if (connect(fd, (struct sockaddr *)&pinfo->client_addr, sizeof(struct sockaddr_in)) < 0)
	{
		perror("second connect in connection handler");
		/* exit(EXIT_FAILURE); */
	}

	/* Set new fd and set BIO to connected */
	BIO_set_fd(SSL_get_rbio(ssl), fd, BIO_NOCLOSE);
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
		return;
	}

	/* Set and activate timeouts */
	timeout.tv_sec = 60;
	timeout.tv_usec = 0;
	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

	while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN))
	{

		reading = 1;
		while (reading)
		{
			len = SRead(ssl, buf, BUFFER_SIZE);
			if (len == 0 || len == 5 || len == 6)
			{
				reading = 0;
			}
			printf("%s\n", buf);
			reading = 0;
		}

		if (len > 0)
		{
			strcpy(buf, "hello from server");
			len = SWrite(ssl, buf, strlen(buf) + 1);
		}
	}

	SSL_shutdown(ssl);

	close(fd);
	free(info);
	SSL_free(ssl);
}

void start_server(int port)
{
	int fd, res = -1;
	struct sockaddr_in server_addr, client_addr;
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	BIO *bio = NULL;
	struct pass_info *info;
	const int on = 1;

	SSL_Confid_Server(&ctx);	
	
	memset(&server_addr, 0, sizeof(struct sockaddr_in));
	
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);

	fd = socket(server_addr.sin_family, SOCK_DGRAM, 0);
	if (fd < 0)
	{
		perror("socket");
		exit(-1);
	}
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, (socklen_t)sizeof(on)) < 0)
	{
		perror("server setsockopt 1");
	}
	if (bind(fd, (const struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) < 0)
	{
		perror("server bind 1");
	}
	
	while (1)
	{
		memset(&client_addr, 0, sizeof(struct sockaddr_in));

		/* Create BIO */
		bio = BIO_new_dgram(fd, BIO_NOCLOSE);

		ssl = SSL_new(ctx);

		SSL_set_bio(ssl, bio, bio);
		SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

		while (res <= 0)
		{
			res = DTLSv1_listen(ssl, (BIO_ADDR *)&client_addr);
			printf("DTLSv1_listen return --> %d\n", res);
		}
		res = 0;

		info = (struct pass_info *)malloc(sizeof(struct pass_info));
		memcpy(&info->server_addr, &server_addr, sizeof(struct sockaddr_in));
		memcpy(&info->client_addr, &client_addr, sizeof(struct sockaddr_in));
		info->ssl = ssl;

		connection_handle(info);
	}

	/* THREAD_cleanup(); */
}

void start_client(char *remote_address, int port)
{
	int fd, i = 0;
	struct sockaddr_in remote_addr, local_addr;
	char buf[BUFFER_SIZE];
	socklen_t len;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;

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

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
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
	bio = BIO_new_dgram(fd, BIO_CLOSE);
	if (connect(fd, (struct sockaddr *)&remote_addr, sizeof(struct sockaddr_in)) < 0)
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
	while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN))
	{
		strcpy(buf, "hello from client");
		len = SWrite(ssl, buf, (strlen(buf) + 1));
		/* Shut down if all messages sent */
		/* if (messagenumber == 0)
		{
			SSL_shutdown(ssl);
		} */

		len = SRead(ssl, buf, sizeof(buf));
		printf("%d byte read\n", len);
	}

	close(fd);
	printf("Connection closed.\n");
}

int main(int argc, char *argv[])
{
	int port = 23232;
	char local_addr[INET_ADDRSTRLEN + 1];
	(void)argc;
	memset(local_addr, 0, INET_ADDRSTRLEN + 1);

	
	printf("Using %s\n", OpenSSL_version(OPENSSL_VERSION));

	if (strcmp(argv[1], "-server") == 0)
	{
		printf("start as server\n");
		start_server(port);
	}
	else
	{
		printf("start as client\n");
		start_client(SERVER_IP, port);
	}
	return 0;
}
