#ifndef NETWORK_UTILS_H_CR4
#define NETWORK_UTILS_H_CR4

#include <stddef.h>

#define MAX2(a,b) (a > b ? a : b)
#define MAX3(m,n,p) ((m) > (n) ? ((m) > (p) ? (m) : (p)) : ((n) > (p) ? (n) : (p)))
#define MAX_COMMAND_LENGTH 1000


typedef struct message_handle
{
    char *input_message;
    char *output_message;
    char *exit_message;
}message_handle_t;

int Logger(int log, const char *log_message);

int SetLogger();

int Random_num(size_t lower, size_t upper);

void ErrorCheck(const char *error_massege, int err_code);

int InputHandler(void *buffer, message_handle_t *handle);

char *GetDefaultGW_Interface();

void Restart_Routing();



#endif /* NETWORK_UTILS_H_CR4 */