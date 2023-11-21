#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024

void handle_error(const char *error_msg)
{
    perror(error_msg);
    exit(EXIT_FAILURE);
}

int main()
{
    int udp_socket;
    struct sockaddr_in server_addr, client_addr;

    /* Create UDP socket */
    if ((udp_socket = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        handle_error("Unable to create socket");
    }

    /* Set up server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(12345); /* Specify the desired port */
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    /* Bind socket to server address */
    if (bind(udp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        handle_error("Unable to bind");
    }

    /* Create SSL context */
    SSL_CTX *ssl_ctx = NULL;
    const SSL_METHOD *ssl_method;
    SSL *ssl;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ssl_method = DTLS_server_method();
    ssl_ctx = SSL_CTX_new(ssl_method);
    if (!ssl_ctx)
    {
        handle_error("Unable to create SSL context");
    }

    /* Load server certificate and private key */
    if (SSL_CTX_use_certificate_file(ssl_ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        handle_error("Unable to load certificate");
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "key.pem", SSL_FILETYPE_PEM) <= 0)
    {
        handle_error("Unable to load private key");
    }

    /* Set up client address structure */
    socklen_t client_addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    /* Perform the DTLS handshake */
    ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, udp_socket);
    if (SSL_accept(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        handle_error("DTLS handshake failed");
    }

    printf("DTLS handshake successful\n");

    /* Read and write data over the secure connection */
    while (1)
    {
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (bytes_received <= 0)
        {
            ERR_print_errors_fp(stderr);
            handle_error("Error reading data");
        }

        printf("Received data: %s\n", buffer);

        /* Echo the received data back to the client */
        int bytes_sent = SSL_write(ssl, buffer, strlen(buffer));
        if (bytes_sent <= 0)
        {
            ERR_print_errors_fp(stderr);
            handle_error("Error sending data");
        }
    }

    /* Clean up */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    close(udp_socket);

    return 0;
}
