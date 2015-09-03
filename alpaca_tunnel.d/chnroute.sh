#!/bin/bash
export PATH="/bin:/sbin:/usr/sbin:/usr/bin:/usr/local/bin"

CUR_DIR=$(cd `dirname $0` && pwd -P)

TABLE=default
ROUTE_DATA=$CUR_DIR/route_data_cidr

case $1 in

a|ad|add)
    OLDGW=`ip route show | grep '^default' | sed -e 's/default via \([^ ]*\).*/\1/'`

    if [ x$OLDGW == x'' ]; then
        OLDGW=`cat /tmp/alpaca_tunnel_gw_ip`
        if [ x$OLDGW == x'' ]; then
            echo "no default gateway found!"
            exit 1
        fi
    fi

    cat $ROUTE_DATA | while read line
    do
        ip route add $line via $OLDGW table $TABLE
    done
    ;;

d|de|del)
    cat $ROUTE_DATA | while read line
    do
        ip route del $line table $TABLE
    done
    ;;

*)
    echo "Usage: $0 add|del"
    ;;

esac