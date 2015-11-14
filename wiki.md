WIKI
====

HOWTO
-----
to do


FAQ
---

#### 1. why iptables don't work?

  A: restart pptp/l2tp tunnel. change iptables rules before vpn client connect to server.
     and try these two rules at the same time:
     iptables -t nat -A POSTROUTING -s 10.5.5.0/24 -o eth0 -j MASQUERADE;
     iptables -t nat -A POSTROUTING -s 10.5.5.0/24 -o eth0 -j SNAT --to-source 10.0.2.15

#### 2. why ip rule/route don't work?

  A: try to change it again.
     Does anyone knows how to receive notification from linux kernel when IPv6 rule changes?
     There is RTMGRP_IPV4_RULE, but it seems that there is no RTMGRP_IPV6_RULE.

DESIGN
------

MODE=server/client/middle, difference between client and server is that client uses less memory.


file path:

1) sh/exe file
1st: none
2nd: $PATH -- /usr/bin, /usr/local/bin
3rd: user specified (bash $path/xxx.sh)

2) user_data(alpacas), chnroute.sh and route_data
1st: user specified
2nd: /etc/alpaca_tunnel.d/* or /usr/local/etc/alpaca_tunnel.d/* (accordingly, if sh/exe is located at $PATH)
3rd: alpaca_tunnel.d/*, the same path with the sh/exe

3) conf file
1st: user specified
2nd: /etc/alpaca_tunnel.conf or /usr/local/etc/alpaca_tunnel.conf (accordingly, if sh/exe is located at $PATH)
3rd: alpaca_tunnel.conf, the same path with the sh/exe


send signal to set valid/invalid of users
send signal to reset timestamp

Packet format:

IP:UDP:ID:More:Type:Length:Timestamp:Sequence:F:Offset:Padding:ICV:IP_Packet:Padding:[More TLV]

tunnel MTU: 2^11 = 2048
11bit: Length
16bit: ID = IP_addr % 65535
16Byte: ICV = AES(header)
ID 0 not used, ID 1 reserved by server.
ID from 2 to 4095(16.255) reserved by middle servers and will not be NATed.

Data Structure at Server:

ID:PSK:valid:repeat:RTT:timestamp:sequence:remote_socket:TCP_dam


tun1  tun2  tun3  tun4
udptun
port1 port2 port3 port4

