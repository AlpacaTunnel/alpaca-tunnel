alpaca-tunnel
=============


alpaca-tunnel is an VPN designed for The Grass Mud Horses, also known as Caonimas. Any Caonima is welcomed to use this software. Anyone who wants to use this tool but agrees with the GFW, go fuck yourself.


Install
-------

Currently only tested on Ubuntu 16.04 and CentOS 7. Depend on systemd. Download the codes and build.

    sudo apt-get update
    sudo apt-get install build-essential make -y
    make && sudo make install


Configuration
-------------

- Conf files are stored in `/usr/local/etc/alpaca-tunnel.d/` by default.
- Edit Mode/ID in `config.json`.
- Edit server addresses and passwords in `secrets`.

alpaca-tunnel supports multiple clients with one server instance. Each server or client has an unique ID, such as 1.1 or 16.4. The format of the ID is just like the format of one half of an IP address. Note that you must allocate smaller IDs for servers, bigger IDs for clients.

Servers and clients must have the same GROUP name.

For the client, you should specify a gateway. You may also specify some forwarders if you have multiple paths, these forwarders will forward packets to the gateway.

The shell version of chnroute is too slow, so I write a C version. Edit chnroute object in the json to use it.


Usage
-----

Show status:

    systemctl status alpaca-tunnel.service

Start:

    sudo systemctl start alpaca-tunnel.service
    sudo /usr/local/etc/alpaca-tunnel.d/chnroute.sh add (optional)

Stop:

    sudo systemctl stop alpaca-tunnel.service
    sudo /usr/local/etc/alpaca-tunnel.d/chnroute.sh del (optional)


Wiki
----

You can find all the documentation in the wiki.md.


License
-------

Copyright (C) 2020 alpaca-tunnel

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.


The json parser was distributed under MIT license, please
refer to <https://github.com/zserge/jsmn>.

The AES lib was copied from <https://github.com/kokke/tiny-AES-c>.


Bugs and Issues
---------------

1. When a client switches the gateway between forwarders, or access more than one forwarders at the same time, it will trigger split horizon. During this time, packets will not be forwarded among the forwarders, and only the direct packets are delivered. So it may slow down the speed. (For each trigger, the log will last for about 10 seconds.)

2. When forwarders set on a server, two clients may not be able to reach each other via the server. If you want to use P2P, don't specify forwarders on the server.


Security Warnings
-----------------

This software is not designed by an security expert, and not designed for strong security. It uses static pre-shared-keys, so there is no perfect forward secrecy, and it's vulnerable to replay attack. Don't rely on it.
