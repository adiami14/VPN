#define _POSIX_C_SOURCE 200809L
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "../../../cyber/include/network_utils.h"

int Logger(int log, const char *log_message)
{
    char buff[1024] = {0};
    strcpy(buff, log_message);
    strcat(buff, __TIME__);
    *(buff + strlen(buff)) = '\n';
    if (write(log, buff, strlen(buff)) < 0)
    {
        perror("write");
        return -1;
    }
    
    printf("log in\n");
    return 0;
}

int SetLogger(const char *path)
{
    int log = open(path, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (log < 0)
    {
        perror("logger open");
        return -1;
    }
    if ((fcntl(log, F_SETFL, O_NONBLOCK) < 0) || log < 0)
    {
        perror("logger fcntl");
        return -1;
    }
    return log;
}

int Random_num(size_t lower, size_t upper)
{
    return ((rand() % (upper - lower + 1)) + lower);
}

void ErrorCheck(const char *error_massege, int err_code)
{
    if (err_code < 0)
    {
        perror(error_massege);
        exit(EXIT_FAILURE);
    }
}

int InputHandler(void *buffer, message_handle_t *handle)
{
    char *ind = strchr(buffer,'\n');
    if (ind == NULL)
    {
        printf("NULL\n");
    }
    *ind = '\0';
    if (strcmp((char *)buffer, handle->input_message) == 0)
    {
        printf("%s\n", handle->output_message);
        return 0;
    }
    else if (strcmp((char *)buffer, handle->exit_message) == 0)
    {
        return -1;
    }

    return 0;
}

char *GetDefaultGW_Interface()
{
    char command[MAX_COMMAND_LENGTH];
    char buffer[128];
    FILE *fp = NULL;

    snprintf(command, sizeof(command), "ip route | awk '/default/ {print $5}'");
    fp = popen(command, "r");
    if (fp == NULL)
    {
        perror("Command execution failed");
        return NULL;
    }

    if (fgets(buffer, sizeof(buffer), fp) != NULL)
    {
        if (buffer[strlen(buffer) - 1] == '\n')
        {
            buffer[strlen(buffer) - 1] = '\0';
        }
        pclose(fp);
        return strdup(buffer);
    }

    pclose(fp);
    return NULL;
}
