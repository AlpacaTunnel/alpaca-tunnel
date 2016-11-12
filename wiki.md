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

#### 1. Mode

    MODE=server/client, for the ELF file, there is no difference between client and server.
    for the shell script, the difference is that client will change the default route to point
    to the tunnel. So be carefully, if you run with client mode on a VPS, you may lose your connection.

#### 2. Sequence number

    The sequence in the header can be as large as 2^24, which means 16Mpps packet rate, or 
    1GB/s to 24GB/s (64byte to 1500byte) rate. Using bit vector to store the sequence, for
    one second, it's 2M byte memory, and two seconds is 4M. If there are 100 peers, this is
    400M memory, which is too large. So I'd like to use a smaller bit vector to store a smaller
    sequence, such as 2^16, 4kpps. This value can be adjusted accordingly. If the seqence number
    in the packet is larger than the bit vector, just drop the packet.

#### 3. NAT rule
    Here is one thing I think that is usefull. Think a peer that has only one external server, but
    may has several middle servers. For example, he may connect from the path client->server1->server9,
    or client->server2->server9, or even client->server1->server2->server3->server9. If he makes sure
    that the external server(server9 in this case) keep unchanged, then when he changes the path or
    routes, the outside servers won't know the change. The NAT port/session will keep unchanged, so a
    connected TCP connection will not be RST and there is no need to reconnect.


file path:

Config file path choose order:
1) if user specify the path with -C, this path will be used.
2) if exe is located at `/usr/bin/`, config will be `/etc/alpaca-tunnel.json`.
3) if exe is located at `/usr/local/bin/`, config will be `/usr/local/etc/alpaca-tunnel.json`.
4) config will be at the same path with exe file.

Secret file path choose order:
1) if user specify the path in json, this path will be used. if this path is a relative path, it's relative to the config json.
2) Otherwise, the secret file MUST be located at the relative path `alpaca-tunnel.d/alpaca-secrets` to the config json, NOT with exe!


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

