#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <strings.h>
#include "../../include/network_utils.h"
#include "../../include/vpn.h"

int main()
{
    vpn_client_t *serv = Setup_Client(5555, SERVER_IP, "./log_vpn_client");

    free(serv);

    return 0;
}
