#ifndef TUNNEL_H_
#define TUNNEL_H_


int tun_alloc(char *dev);
int tun_up(char *dev);
int tun_mtu(char *dev, int mtu);
int tun_addip(char *dev, char *ip, int mask);


#endif
