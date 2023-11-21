#ifndef VPN_SSL_H
#define VPN_SSL_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

#define CERT_SERVER ("cert/server-cert.pem")
#define KEY_SERVER ("cert/server-key.pem")

#define CERT_CLIENT ("cert/client-cert.pem")
#define KEY_CLIENT ("cert/client-key.pem")
#define COOKIE ("COOKIE_JOE")


typedef struct sockaddr_in sai_t;
typedef struct sockaddr sa_t;


typedef struct ssl_handler
{
    SSL_CTX *ctx;
    SSL *ssl;
    SSL_METHOD *method;
    struct sockaddr_in server_addr;
}ssl_handler_t;

ssl_handler_t *SSL_Setup();

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len);

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len);

int verify_cert(int ok, X509_STORE_CTX *ctx);

void SSL_Confid_Server(SSL_CTX **ctx);

void ShowCerts(SSL *ssl);

void LoadCertificates(SSL_CTX *ctx, char *CertFile, char *KeyFile);

int SConnect(SSL *ssl);

int SWrite(SSL *ssl, char buf[], int length);

int SRead(SSL *ssl, char buf[], int length);

int SAccept(SSL *ssl);

int handle_socket_error();
#endif /* VPN_SSL_H */
