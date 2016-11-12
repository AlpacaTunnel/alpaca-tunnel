#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <net/if.h>

#include "tunnel.h"
#include "log.h"


int tun_alloc(char *dev) 
{
    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";

    if( (fd = open(clonedev, O_RDWR)) < 0 ) 
    {
        ERROR(errno, "open /dev/net/tun");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (*dev) 
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) 
    {
        ERROR(errno, "ioctl(TUNSETIFF): %s", dev);
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);

    return fd;
}

int tun_up(char *dev)
{
    char * cmd = (char *)malloc(100 + IFNAMSIZ);
    sprintf(cmd, "ip link set dev %s up", dev);
    int rc = system(cmd);
    free(cmd);

    return rc;
}

int tun_mtu(char *dev, int mtu)
{
    char * cmd = (char *)malloc(100 + IFNAMSIZ);
    sprintf(cmd, "ip link set dev %s mtu %d", dev, mtu);
    int rc = system(cmd);
    free(cmd);

    return rc;
}

int tun_addip(char *dev, char *ip, int mask)
{
    // max length of IPv6 address is 39 bytes, so 100 is enough here.
    char * cmd = (char *)malloc(100 + IFNAMSIZ);
    sprintf(cmd, "ip addr add %s/%d dev %s", ip, mask, dev);
    int rc = system(cmd);
    free(cmd);

    return rc;
}

