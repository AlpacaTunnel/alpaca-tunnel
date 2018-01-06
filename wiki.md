WIKI
====

HOWTO
-----
todo


FAQ
---


#### 1. Why iptables don't work?

A: Restart pptp/l2tp tunnel, change iptables rules before vpn client connect to server, and try these two rules at the same time:

    iptables -t nat -A POSTROUTING -s 10.17.0.0/16 -j MASQUERADE;

    iptables -t nat -A POSTROUTING -s 10.17.0.0/16 -j SNAT --to-source 10.0.2.15

And if you have Docker installed, it will change the filter table in FORWARD chain to default DROP target. So you may also enable FORWARD rule:

    iptables -A FORWARD -s 10.17.0.0/16 -j ACCEPT

    iptables -A FORWARD -d 10.17.0.0/16 -j ACCEPT


#### 2. Why ip rule/route don't work?

A: Try to change it again.

BTW, does anyone know how to receive notification from linux kernel when IPv6 rule changes? There is RTMGRP_IPV4_RULE, but it seems that there is no RTMGRP_IPV6_RULE.


DESIGN
------


#### 1. Mode

MODE=server/client. The peers with smaller IDs are considered as servers.

I tried to make the peers in the system as equal as possible, but at last I found it's much easier if I left mode in the system.

The main difference between client and server is route and forwarder.

First, the client will change the default route to point to the tunnel. So be carefully, if you run the programm with client mode on a VPS, you may lose your connection.

Then, when packets are sent from client to server, they will be sent to the forwarders (if there are any). But when the packets are send from server to clients, the forwarders are not used. (See the details below #2.)


#### 2. Gateway and Forwarders

When a packet enters the tunnel system, it's because the OS has set the route to some address in the tunnel, that address is the gateway, and we know its ID. The gateway ID is then set as the dst_id in the header. The src_id in the header is always the sender's ID.

When dst_id > src_id (from server to client), always send the packet to the dst_id directly, no matter this packet was read from tunnel or received from socket, and don't check the forwarder.

When dst_id < src_id (from client to server), it's quite complicated. I tried hard to make the rules simple yet powerful.

When a peer reads a packet from the tunnel device:

    a1) If the peer specifies no forwarders, the packet should be sent directly to the gateway (dst_id).

    a2) If the peer specifies some forwarders, then the packet should be sent to these forwarders.

When a peer receives a packet from the UDP socket, it should do this way:

    b1) If dst_id in header equals the peer's ID, then write it to the tunnel device. (This step can be optimized, see below #3.)

    b2) If dst_id in header does NOT equal the peer's ID, and there are no forwarders, then send it to dst_id.

    b3) If dst_id in header does NOT equal the peer's ID, and there are forwarders, then send to the forwarders.

By applying these rules, we are given the privilege of choosing gateway to the clients. And two peers can even do p2p communication via a server.

Because there are forwarders, there are different paths in the header. The first path is always the peer's direct address (no forwarders involved). When load secrets from file, a peer's first path is statically set if it has an address. When a client send a packet to server, it set path index to 0 if no forwarders are specified (or the forwarder is the server).

In the above rules, when a packet is sent to forwarders, it's always sent to the first path. And when a packet is sent directly to a none-forwarder, it's sent to all available paths.


#### 3. Routing Optimization

Consider the above `b1`, the packet is written to the OS. What if the OS has a PBR that send the packet back to the tunnel?

The packet will then enter the tunnel again and be sent to another peer (the new gateway in the PBR). If iptables rule is properly applied, the source IP will be changed to the tunnel's IP, and a new NAT session will be added.

To optimize this, the peer can query the routing table first, and choose not to write the packet to the OS. Instead, it can replace the dst_id with the new gateway ID, and send it to the new gateway. Forwarder can also be used. (But it can not replace the src_id, otherwise the packet cann't be sent back to its original peer.)

For `b2` and `b3`, don't change the dst_id even if there is PBR. Otherwise the packet may end up on different peers if there are more than one forwarders on the orignal peer.

But I don't want to implement this optimization now, just let the iptables do the work.


#### 3. TCP RST

With gateway and forwarders, the tunnel system actually becomes a inner routing system between peers. And it brings some features that's usefull.

Think a peer that has only one gateway server, but may has several forwarding servers. For example, he may connect from the path client->server1->server9, or client->server2->server9, or even client->server1->server2->server3->server9. If he makes sure that the gateway server(server9 in this case) keeps unchanged, then when he changes the path or forwarders, the outside servers won't know the change. The NAT port/session on the gateway will keep unchanged, so a connected TCP connection will not be RST and there is no need to reconnect.


#### 4. TCP Optimization

I had a guess. If I delay the TCP ack on the tunnel receive point, the RTO on the TCP endpoint will grow larger. If I retrans the lost packet before this RTO, I may change the connection to a long fat tunnel and speed up the TCP.

But Google then published their BBR algorithm. It's really fast, and it's not sensitive to delay. So I think there is no need to implement the TCP optimization again. Use BBR inside the tunnel. For example a socks5 proxy or http proxy, or even a TCP based VPN tunnel.

Since retrans is unnecessary, I removed it.

Actually in my experience, I found duplicate send the packets with a delay can bring more throughput. Why with a delay? To make two packets less relevant.

Send packets with two different paths should have the same effect. That's why I add forwarders.

Waste a half bandwidth to get a higher throughput, choose your own way.


#### 5. File Path

Config file path choose order:

    1) if user specify the path with -C, this path will be used.
    2) if exe is located at `/usr/bin/`, config will be `/etc/alpaca-tunnel.d/config.json`.
    3) if exe is located at `/usr/local/bin/`, config will be `/usr/local/etc/alpaca-tunnel.d/config.json`.
    4) config will be at the relative path `./alpaca-tunnel.d/` to the exe file.
    
Secret file path choose order:

    1) If user specifies the path in json, this path will be used. If this path is a relative path, it's relative to the config json.
    2) Otherwise, the secret file MUST be located at the relative path `./secrets.txt` to the config json, NOT with exe!


#### 6. Sequence Number

The sequence in the header can be as large as 2^20, which means 1Mpps packet rate, or 512Mbps to 12Gbps (64byte to 1500byte) rate. 

