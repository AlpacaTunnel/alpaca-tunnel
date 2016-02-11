AlpacaTunnel
============


AlpacaTunnel is an VPN designed for The Grass Mud Horses, also known as
Caonimas. Any Caonima is welcomed to use this software. Anyone who wants
to use this tool but agrees with the GFW, go fuck yourself.


Install
-------

Currently only tested on Ubuntu and CentOS.
Download the codes and build.

    sudo apt-get update
    sudo apt-get install build-essential make bc -y
    make && sudo make install


Configuration
-------------

- Conf files are stored in `/usr/local/etc` by default.
- Edit Mode/ID in `alpaca_tunnel.conf`.
- Edit server addresses and passwords in `alpaca_secrets`.

AlpacaTunnel supports multiple clients with one server instance. Each server
or client has an unique ID, such as 1.1 or 16.4. The format of the ID is just
like the format of one half of an IP address. Note that you must allocate
smaller IDs for servers, bigger IDs for clients.

Servers and clients must have the same GROUP name.


Usage
-----

Search running instances:

    alpaca_tunnel search

Start:

    sudo alpaca_tunnel up
    sudo /usr/local/etc/alpaca_tunnel.d/chnroute.sh add

Stop:

    sudo alpaca_tunnel down
    sudo /usr/local/etc/alpaca_tunnel.d/chnroute.sh del


Wiki
----

You can find all the documentation in the wiki.md.


License
-------

Copyright (C) 2015 AlpacaTunnel

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


Bugs and Issues
----------------
It's the end of the Year of the Goat, but it's not the end of the
alpaca tunnel.






