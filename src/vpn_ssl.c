#include <stdio.h>       /*standard i/o*/
#include <errno.h>       /*USING THE ERROR LIBRARY FOR FINDING ERRORS*/
#include <stdlib.h>      /*FOR MEMORY ALLOCATION */
#include <string.h>      /*using fgets funtions for geting input from user*/
#include <resolv.h>      /*server to find out the runner's IP address*/
#include <netdb.h>       /*definitions for network database operations */
#include <openssl/ssl.h> /*using openssl function's and certificates and configuring them*/
#include <openssl/err.h> /* helps in finding out openssl errors*/
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#include "../../../cyber/include/vpn_ssl.h"

#define FAIL -1     /*for error output == -1 */
#define BUFFER 1024 /*buffer for reading messages*/

/* creating and setting up ssl context structure */
ssl_handler_t *SSL_Setup()
{

    ssl_handler_t *ssl = malloc(sizeof(ssl_handler_t));
    if (!ssl)
    {
        perror("Setup SSL");
        exit(EXIT_FAILURE);
    }

    SSL_library_init();
    OpenSSL_add_all_algorithms();                 /* Load cryptos, et.al. */
    SSL_load_error_strings();                     /* Bring in and register error messages */
                                                
    ssl->ctx = SSL_CTX_new(DTLS_server_method()); /* Create new context */
    if (!ssl->ctx)
    {
        perror("SSL context");
        exit(EXIT_FAILURE);
    }
    return ssl;
}

/*show the ceritficates to server and
match them but here we are not using any client certificate*/
void ShowCerts(SSL *ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if (cert != NULL)
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line); /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);      /* free the malloc'ed string */
        X509_free(cert); /* free the malloc'ed certificate copy */
    }
    else
    {
        printf("Info: No client certificates configured.\n");
    }
}

/* load a certificate into an SSL_CTX structure */
void LoadCertificates(SSL_CTX *ctx, char *CertFile, char *KeyFile)
{
    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
    {
        perror("SSL_CTX_use_certificate_file");
        exit(EXIT_FAILURE);
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        perror("SSL_CTX_use_PrivateKey_file");
        exit(EXIT_FAILURE);
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
    {
        perror("Private key does not match the public certificate");
        exit(EXIT_FAILURE);
    }
}

/* Generate cookie. Returns 1 on success, 0 otherwise */
int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    (void)ssl;
    memcpy(cookie, "cookie", 6);
    *cookie_len = 6;

    return 1;
}

/* Verify cookie. Returns 1 on success, 0 otherwise */
int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
    (void)ssl;
    printf("Verify Cookie --> %s, len --> %d\n", cookie, cookie_len);

    return 1;
}

/* Certificate verification. Returns 1 if trusted, else 0 */
int verify_cert(int ok, X509_STORE_CTX *ctx)
{
    (void)ok;
    (void)ctx;
    return 1;
}

/* Wrap connect with error handling */
int SConnect(SSL *ssl)
{
    int retval = SSL_connect(ssl);
    if (retval <= 0)
    {
        switch (SSL_get_error(ssl, retval))
        {
        case SSL_ERROR_ZERO_RETURN:
            fprintf(stderr, "SSL_connect failed with SSL_ERROR_ZERO_RETURN\n");
            break;
        case SSL_ERROR_WANT_READ:
            fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_READ\n");
            break;
        case SSL_ERROR_WANT_WRITE:
            fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_WRITE\n");
            break;
        case SSL_ERROR_WANT_CONNECT:
            fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_CONNECT\n");
            break;
        case SSL_ERROR_WANT_ACCEPT:
            fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_ACCEPT\n");
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:
            fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_X509_LOOKUP\n");
            break;
        case SSL_ERROR_SYSCALL:
            fprintf(stderr, "SSL_connect failed with SSL_ERROR_SYSCALL\n");
            break;
        case SSL_ERROR_SSL:
            fprintf(stderr, "SSL_connect failed with SSL_ERROR_SSL\n");
            break;
        default:
            fprintf(stderr, "SSL_connect failed with unknown error\n");
            break;
        }
    }
    return retval;
}

int SWrite(SSL *ssl, char buf[], int length)
{
    int len = SSL_write(ssl, buf, length);

    switch (SSL_get_error(ssl, len))
    {
    case SSL_ERROR_NONE:
        printf("wrote %d bytes\n", (int)len);
        break;
    case SSL_ERROR_WANT_WRITE:
        /* Just try again later */
        break;
    case SSL_ERROR_WANT_READ:
        /* continue with reading */
        break;
    case SSL_ERROR_SYSCALL:
        printf("Socket write error: ");
        if (!handle_socket_error())
            exit(1);
        /* reading = 0; */
        break;
    case SSL_ERROR_SSL:
        printf("SSL write error: ");
        printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, len));
        exit(1);
        break;
    default:
        printf("Unexpected error while writing!\n");
        exit(1);
        break;
    }
    return len;
}

int SRead(SSL *ssl, char buf[], int length)
{
    int len = SSL_read(ssl, buf, length);
    switch (SSL_get_error(ssl, len))
    {
    case SSL_ERROR_NONE:
        printf("read %d bytes\n", (int)len);
        break;
    case SSL_ERROR_WANT_READ:
        /* Stop reading on socket timeout, otherwise try again */
        if (BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL))
        {
            printf("Timeout! No response received.\n");
        }
        break;
    case SSL_ERROR_ZERO_RETURN:
        break;
    case SSL_ERROR_SYSCALL:
        printf("Socket read error: ");
        if (!handle_socket_error())
            exit(1);
        break;
    case SSL_ERROR_SSL:
        printf("SSL read error: ");
        printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, len));
        exit(1);
        break;
    default:
        printf("Unexpected error while reading!\n");
        exit(1);
        break;
    }
    return len;
}

int SAccept(SSL *ssl)
{
    int ret = SSL_accept(ssl);
    if (ret != 1)
    {
        
        int sslError = SSL_get_error(ssl, ret);


        switch (sslError)
        {
            case SSL_ERROR_SSL:
                printf("SSL_accept failed: SSL_ERROR_SSL\n");
                break;
            case SSL_ERROR_WANT_READ:
                printf("SSL_accept failed: SSL_ERROR_WANT_READ\n");
                break;
            case SSL_ERROR_WANT_WRITE:
                printf("SSL_accept failed: SSL_ERROR_WANT_WRITE\n");
                break;
            case SSL_ERROR_ZERO_RETURN:
                printf("SSL_accept failed: SSL_ERROR_ZERO_RETURN\n");
                break;
            case SSL_ERROR_WANT_CONNECT:
                printf("SSL_accept failed: SSL_ERROR_WANT_CONNECT\n");
                break;
            case SSL_ERROR_WANT_ACCEPT:
                printf("SSL_accept failed: SSL_ERROR_WANT_ACCEPT\n");
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                printf("SSL_accept failed: SSL_ERROR_WANT_X509_LOOKUP\n");
                break;
            case SSL_ERROR_SYSCALL:
            default:
                printf("SSL_accept failed with unknown error\n");
                break;
        }
    }

    return ret;
}

void SSL_Confid_Server(SSL_CTX **ctx)
{
    
	SSL_load_error_strings();
    *ctx = SSL_CTX_new(DTLS_server_method());
	LoadCertificates(*ctx, CERT_SERVER, KEY_SERVER);
	SSL_CTX_set_verify(*ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, verify_cert);
	SSL_CTX_set_cookie_generate_cb(*ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(*ctx, verify_cookie);

    return;
}

int handle_socket_error()
{
	switch (errno)
	{
	case EINTR:
		/* Interrupted system call.
		 * Just ignore.
		 */
		printf("Interrupted system call!\n");
		return 1;
	case EBADF:
		/* Invalid socket.
		 * Must close connection.
		 */
		printf("Invalid socket!\n");
		return 0;
		break;
#ifdef EHOSTDOWN
	case EHOSTDOWN:
		/* Host is down.
		 * Just ignore, might be an attacker
		 * sending fake ICMP messages.
		 */
		printf("Host is down!\n");
		return 1;
#endif
#ifdef ECONNRESET
	case ECONNRESET:
		/* Connection reset by peer.
		 * Just ignore, might be an attacker
		 * sending fake ICMP messages.
		 */
		printf("Connection reset by peer!\n");
		return 1;
#endif
	case ENOMEM:
		/* Out of memory.
		 * Must close connection.
		 */
		printf("Out of memory!\n");
		return 0;
		break;
	case EACCES:
		/* Permission denied.
		 * Just ignore, we might be blocked
		 * by some firewall policy. Try again
		 * and hope for the best.
		 */
		printf("Permission denied!\n");
		return 1;
		break;
	default:
		/* Something unexpected happened */
		printf("Unexpected error! (errno = %d)\n", errno);
		return 0;
		break;
	}
	return 0;
}