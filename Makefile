all:
	gcc -std=gnu99 main.c aes.c route.c bitmap.c -lpthread -o AlpacaTunnel -Wall -O3

clean:
	rm -f AlpacaTunnel

install:
	mkdir -p /usr/local/bin
	cp -n AlpacaTunnel /usr/local/bin/
	cp -n alpaca_tunnel.sh /usr/local/bin/alpaca_tunnel

	mkdir -p /usr/local/etc/alpaca_tunnel.d
	cp -n alpaca_tunnel.conf /usr/local/etc/
	cp -n alpaca_tunnel.d/* /usr/local/etc/alpaca_tunnel.d/
	chown root:root /usr/local/etc/alpaca_tunnel.d/alpaca_secrets
	chmod 600 /usr/local/etc/alpaca_tunnel.d/alpaca_secrets

uninstall:
	rm -f /usr/local/bin/AlpacaTunnel
	rm -f /usr/local/bin/alpaca_tunnel
	rm -f /usr/local/etc/alpaca_tunnel.conf

