all:
	gcc -std=gnu11 main.c aes.c log.c secret.c ip.c tunnel.c cmd_helper.c route.c config.c data-struct/*.c -lpthread -lm -o alpaca-tunnel -Wall -O3

debug:
	gcc -std=gnu11 main.c aes.c log.c secret.c ip.c tunnel.c cmd_helper.c route.c config.c data-struct/*.c -lpthread -lm -o alpaca-tunnel -Wall -g

test:
	gcc -std=gnu11 test.c aes.c log.c secret.c ip.c tunnel.c cmd_helper.c route.c config.c data-struct/*.c -lpthread -lm -o alpaca-tunnel -Wall -g

clean:
	rm -f alpaca-tunnel

install:
	mkdir -p /usr/local/etc/alpaca-tunnel.d
	cp -n alpaca-tunnel.d/* /usr/local/etc/alpaca-tunnel.d/
	chown root:root /usr/local/etc/alpaca-tunnel.d/secrets.txt
	chmod 600 /usr/local/etc/alpaca-tunnel.d/secrets.txt

	mkdir -p /usr/local/bin
	cp -n alpaca-tunnel /usr/local/bin/
	cp -n alpaca-tunnel.service /etc/systemd/system/
	systemctl enable alpaca-tunnel.service

uninstall:
	systemctl disable alpaca-tunnel.service || :
	rm -f /etc/systemd/system/alpaca-tunnel.service
	rm -f /usr/local/bin/alpaca-tunnel

purge:
	systemctl disable alpaca-tunnel.service || :
	rm -f /etc/systemd/system/alpaca-tunnel.service
	rm -f /usr/local/bin/alpaca-tunnel

	rm -f /usr/local/etc/alpaca-tunnel.d/config.json
	rm -f /usr/local/etc/alpaca-tunnel.d/secrets.txt
	rm -f /usr/local/etc/alpaca-tunnel.d/chnroute.sh
	rm -f /usr/local/etc/alpaca-tunnel.d/route_data_cidr
	rmdir /usr/local/etc/alpaca-tunnel.d/

