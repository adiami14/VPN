#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 4096

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    method = TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        fprintf(stderr, "Unable to create SSL context\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int main()
{
    int server_fd;
    struct sockaddr_in server_addr;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    char buffer[BUFFER_SIZE];

    /* Create UDP socket */
    if ((server_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    /* Configure server address */
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(12345);
    server_addr.sin_addr.s_addr = inet_addr("SERVER_IP_ADDRESS");

    /* Create SSL context */
    ssl_ctx = create_context();

    /* Create SSL object */
    ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, server_fd);

    /* Perform SSL handshake */
    if (SSL_connect(ssl) <= 0)
    {
        perror("SSL handshake failed");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Send data to server */
    const char *request = "Hello from client!";
    SSL_write(ssl, request, strlen(request));

    /* Receive response from server */
    int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_received > 0)
    {
        buffer[bytes_received] = '\0';
        printf("Received message from server: %s\n", buffer);
    }

    /* Clean up */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(server_fd);
    SSL_CTX_free(ssl_ctx);

    return 0;
}
