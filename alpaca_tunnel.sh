#!/bin/bash
export PATH="/bin:/sbin:/usr/sbin:/usr/bin:/usr/local/bin"

CUR_DIR=$(cd `dirname $0` && pwd -P)

EXE_PATH=$CUR_DIR
CONF_PATH=$CUR_DIR
if [ $CUR_DIR == "/usr/local/bin" ]; then
    CONF_PATH=/usr/local/etc
elif [ $CUR_DIR == "/usr/bin" ];then
    CONF_PATH=/etc
fi

CONF_FILE=$CONF_PATH/alpaca_tunnel.conf
if [ -r $CONF_FILE ]; then
    source $CONF_FILE
else
    echo "configure file not available!"
    exit 1
fi
#KEY_MD5=`echo $SELF_KEY | md5sum | awk '{ printf $1 }'`
KEY_MD5=$SELF_KEY

#TUN_INDEX: each tun interface indicates one tunnel instance.
#Change it when you want to run multiple tunnel instances at the same time.
TUN_INDEX=1

NETID=17
TUN_IP=10.$NETID.$SELF_ID
TUN_GW=10.$NETID.0.1

DNS_ADDR_LOCAL=114.114.114.114
EXE_NAME=AlpacaTunnel
TUN_PREFIX=alptun
TUNIF=$TUN_PREFIX$TUN_INDEX
TUN_MASK=16
TUN_MTU=1408
TCPMSS=1356

HEADER_LEN=60       #20+8+32
BACKUP_PREFIX=running_backup_
BACKUP_PATH=/tmp/running_backup_$TUNIF
mkdir -p $BACKUP_PATH
BACKUP_SCRIPT=$BACKUP_PATH/alpaca_tunnel.sh
BACKUP_CONF=$BACKUP_PATH/alpaca_tunnel.conf
BACKUP_GW_IP=/tmp/alpaca_tunnel_gw_ip
LOGFILE=/var/log/alpaca_tunnel.log


usage()
{
    #Usage: $EXE_NAME [-s|-c host] [-p port] [-k psk] [-i tun]
    echo "Usage: $0 up|down|search"
    return 1
}

check_tun_name()
{
    [ -z $1 ] && return 0
    local tunif=$1
    ifconfig -a | grep $tunif > /dev/null
    if [ $? == 0 ]; then
        for ifname in `ifconfig -a | grep $tunif | awk '{print $1}'`; do 
            [ $tunif == $ifname ] && return 1   #there is a same tun
            return 2    #there is a tun with the same prefix
        done
    fi
    return 0    #no such tun
}

check_ip_format()
{
    local ipaddr=$1
    echo $ipaddr | grep "^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}$" > /dev/null
    [ $? == 1 ] && return 1    #not in ip format

    a=`echo $ipaddr | awk -F. '{print $1}'`
    b=`echo $ipaddr | awk -F. '{print $2}'`
    c=`echo $ipaddr | awk -F. '{print $3}'`
    d=`echo $ipaddr | awk -F. '{print $4}'`

    #not nomoral ip address
    [ $a -gt 239 -o $a -le 0 -o $b -gt 255 -o $b -lt 0 -o $c -gt 255 -o $c -lt 0 -o $d -gt 254 -o $d -le 0 ] && return 2

    [ $a -ge 224 ] && return 3    #multi-cast

    [ $a -eq 127 ] && return 4    #loopback

    return 0    #valid ip format
}

convert_ip_dec2bin()
{
    #input:     128.1.1.5
    #output:    10000000000000010000000100000101

    local ipaddr=$1
    check_ip_format $1
    [ $? != 0 ] && return 1

    a=`echo $ipaddr | awk -F. '{print $1}'`
    b=`echo $ipaddr | awk -F. '{print $2}'`
    c=`echo $ipaddr | awk -F. '{print $3}'`
    d=`echo $ipaddr | awk -F. '{print $4}'`
    
    a2=`echo "obase=2;$a" | bc`
    b2=`echo "obase=2;$b" | bc`
    c2=`echo "obase=2;$c" | bc`
    d2=`echo "obase=2;$d" | bc`

    bit8map=00000000

    bita=${bit8map:0:$((8 - ${#a2}))}$a2
    bitb=${bit8map:0:$((8 - ${#b2}))}$b2
    bitc=${bit8map:0:$((8 - ${#c2}))}$c2
    bitd=${bit8map:0:$((8 - ${#d2}))}$d2

    echo $bita$bitb$bitc$bitd
    return 0    #valid mask format
}

check_ip_overlap()
{
    # 1.1.1.5/24 == 1.1.1.6/24, is overlap, return 0

    local ip1=`echo $1 | awk -F/ '{print $1}'`
    local ip2=`echo $2 | awk -F/ '{print $1}'`
    local mask1=`echo $1 | awk -F/ '{print $2}'`
    local mask2=`echo $2 | awk -F/ '{print $2}'`

    ip1=`convert_ip_dec2bin $ip1`
    [ $? != 0 ] && return 1
    ip2=`convert_ip_dec2bin $ip2`
    [ $? != 0 ] && return 1
 
    mask=$((mask1<mask2?mask1:mask2))

    net1=${ip1:0:$mask}
    net2=${ip2:0:$mask}

    [ $net1 != $net2 ] && return 1
    return 0    #overlap
}

kill_tunnel()
{
    #only kill process bind to $tun_kill
    local tun_kill=$1
    pid=`ps ax | grep $EXE_NAME | awk /-i\ $tun_kill$/ | awk '{print $1}'`

    if [ $MODE == server ] || [ $MODE == middle_server ]; then
        ps $pid | grep -v grep | grep $EXE_NAME | grep -e "-c" > /dev/null
        if [ $? == 0 ]; then
            echo "mode doesn't match, process is in client mode!"
            return 1
        fi
    fi
    
    if [ $MODE == client ] || [ $MODE == middle_client ]; then
        ps $pid | grep -v grep | grep $EXE_NAME | grep -e "-s" > /dev/null
        if [ $? == 0 ]; then
            echo "mode doesn't match, process is in server mode!"
            return 1
        fi
    fi

    if [ x$pid == x"" ]; then
        echo "cann't find pid of tunnel $tun_kill, nothing to kill!"
        return 0
    fi

    kill $pid
    for t in `seq 3`; do
        ps $pid > /dev/null
        if [ $? == 0 ]; then
            sleep $t
            kill $pid
        fi
    done
    for t in `seq 2`; do
        ps $pid > /dev/null
        if [ $? == 0 ]; then
            sleep $t
            echo "kill by force!"
            kill -9 $pid
        fi
    done

    ps $pid > /dev/null
    [ $? == 0 ] && return 1
    return 0
}

serverup()
{
    check_tun_name $TUNIF
    if [ $? != 0 ]; then
        echo "$TUNIF already exists, nothing to do!"
        return 1
    fi

    ipmasklist=`ip addr show | grep inet | awk '{print $2}'`
    for im in $ipmasklist; do
        check_ip_overlap $im $TUN_IP/$TUN_MASK
        if [ $? == 0 ]; then
            echo "tunnel network overlaps with $im, nothing to do!"
            return 1
        fi
    done

    #should check all tables
    default_gw_dev=`ip route show | grep '^default' | sed -e 's/.*dev \([^ ]*\).*/\1/'`
    gwmtu=`ifconfig $default_gw_dev | grep MTU | sed -e 's/.*MTU:\([^ ]*\).*/\1/'`
    gwmtu=$((gwmtu-HEADER_LEN))
    TUN_MTU=$((gwmtu<TUN_MTU?gwmtu:TUN_MTU))

    if [ middle_server == $MODE ]; then
        search_instance client > /dev/null
        if [ $? == 0 ]; then
            echo "Warning: no client instance running, run the following command after start the client:"
            echo "#-------Beginning of command-------"
            echo "iptables -t nat -A POSTROUTING -s $TUN_IP/$TUN_MASK -o \$client_tunif -j SNAT --to-source \$client_tunip"
        else
            echo "please run the following command manually:"
            echo "#-------Beginning of command-------"
            tunlist=`ifconfig | grep $TUN_PREFIX | awk '{print $1}'`
            for tunif in $tunlist; do
                ps -ef | grep $tunif | grep -v grep | grep -e "-c" > /dev/null
                if [ $? == 0 ]; then   #client
                    tunip=`ip addr show $tunif | grep inet | awk '{print $2}' | awk -F/ '{print $1}'`
                    gwmtu=`ifconfig $tunif | grep MTU | sed -e 's/.*MTU:\([^ ]*\).*/\1/'`
                    TUN_MTU=$((gwmtu<TUN_MTU?gwmtu:TUN_MTU))
                    echo "iptables -t nat -A POSTROUTING -s $TUN_IP/$TUN_MASK -o $tunif -j SNAT --to-source $tunip"
                fi
            done
        fi
        echo "ip rule add from $TUN_IP/$TUN_MASK table xxx"
        echo "ip route add default dev \$client_tunif table xxx"
        echo "chnroute.sh add"
        echo "#---------End of command--------"
    fi

    ip tuntap add dev $TUNIF mode tun
    if [ $? != 0 ]; then
        echo "creat $TUNIF failed, nothing to do!"
        return 1
    fi
    ip link set $TUNIF up
    ip link set $TUNIF mtu $TUN_MTU
    ip addr add $TUN_IP/$TUN_MASK dev $TUNIF
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    iptables -t nat -A POSTROUTING -s $TUN_IP/$TUN_MASK -o $default_gw_dev -j MASQUERADE
    iptables -A FORWARD -p tcp --syn -s $TUN_IP/$TUN_MASK -j TCPMSS --set-mss $TCPMSS

    #TUNIF must be put at the end of the line.
    nohup $EXE_PATH/$EXE_NAME -s -p $SERVER_PORT -k $KEY_MD5 -g $GROUP -n $SELF_ID -i $TUNIF >> $LOGFILE &
    sleep 0.2
    ps aux | grep $! | grep -v grep > /dev/null
    if [ $? == 0 ]; then
        cp -f $0 $BACKUP_SCRIPT > /dev/null
        cp -f $CONF_FILE $BACKUP_CONF > /dev/null
        ifconfig $TUNIF | grep inet | awk '{print $2"\t"$NF}'
        echo "server's tunnel MTU is: $TUN_MTU."
        echo "$EXE_NAME started on port $SERVER_PORT with $TUNIF."
        return 0
    else
        iptables -t nat -D POSTROUTING -s $TUN_IP/$TUN_MASK -o $default_gw_dev -j MASQUERADE
        iptables -D FORWARD -p tcp --syn -s $TUN_IP/$TUN_MASK -j TCPMSS --set-mss $TCPMSS
        ip tuntap del dev $TUNIF mode tun
        cat $LOGFILE | tail -n 1
        echo "$EXE_NAME failed to start with $TUNIF!"
        return 1
    fi
}

serverdown()
{
    check_tun_name $TUNIF
    if [ $? == 0 ]; then
        echo "no $TUNIF anymore, nothing to do!"
        return 0
    fi

    search_instance server
    if [ $? == 0 ]; then
        echo "Warning: no server instance running anymore!"
    else
        kill_tunnel $TUNIF
        if [ $? == 1 ]; then
            echo "$EXE_NAME failed to exit with $TUNIF."
            return 1
        fi
    fi

    default_gw_dev=`ip route show | grep '^default' | sed -e 's/.*dev \([^ ]*\).*/\1/'`
    iptables -t nat -D POSTROUTING -s $TUN_IP/$TUN_MASK -o $default_gw_dev -j MASQUERADE
    iptables -D FORWARD -p tcp --syn -s $TUN_IP/$TUN_MASK -j TCPMSS --set-mss $TCPMSS
    ip tuntap del dev $TUNIF mode tun
    if [ $? != 0 ]; then
        echo "delete $TUNIF failed!"
        echo "$EXE_NAME failed to exit with $TUNIF."
        return 1
    fi
    rm -rf $BACKUP_PATH > /dev/null
    echo "$EXE_NAME exited with $TUNIF."
    if [ middle_server == $MODE ]; then
        echo "check the iptables & ip rules and delete the following if needed:"
        echo "#-------Beginning of command-------"
        echo "iptables -t nat -D POSTROUTING -s $TUN_IP/$TUN_MASK -o \$client_tunif -j SNAT --to-source \$client_tunip"
        echo "ip rule del from $TUN_IP/$TUN_MASK table xxx"
        echo "ip route del default dev \$client_tunif table xxx"
        echo "chnroute.sh del"
        echo "#---------End of command--------"
    fi
    return 0
}

clientup()
{
    check_ip_format $SERVER_ADDR
    if [ $? != 0 ]; then
        ip=`nslookup $SERVER_ADDR`
        if [ $? != 0 ]; then
            echo "server name lookup failed, check your server address."
            return 1
        fi
        SERVER_ADDR=`echo $ip | awk '{print $NF}'`
    fi

    check_tun_name $TUNIF
    if [ $? != 0 ]; then
        echo "$TUNIF already exists, nothing to do!"
        return 1
    fi
    
    search_instance client > /dev/null
    if [ client == $MODE ] && [ $? != 0 ]; then
        echo "there is already one client instance running, nothing to do!"
        return 1
    fi

    iplist=`ip addr show | grep inet | awk '{print $2}'`
    for ip in $iplist; do
        check_ip_overlap $ip $TUN_IP/$TUN_MASK
        if [ $? == 0 ]; then
            echo "tunnel network overlaps with $ip, nothing to do!"
            return 1
        fi
    done

    iplist=`ip addr show | grep inet | awk '{print $2}' | awk -F/ '{print $1}'`
    for ip in $iplist; do
        if [ $SERVER_ADDR == $ip ]; then
            echo "check if this is server, don't run client on a server!"
            return 1
        fi
    done

    server_gw_dev=`ip route get $SERVER_ADDR | grep dev | sed -e 's/.*dev \([^ ]*\).*/\1/'`
    if [ x$server_gw_dev == x"" ]; then
        echo "no route to server, nothing to do!"
        return 1
    fi
    gwmtu=`ifconfig $server_gw_dev | grep MTU | sed -e 's/.*MTU:\([^ ]*\).*/\1/'`
    gwmtu=$((gwmtu-HEADER_LEN))
    TUN_MTU=$((gwmtu<TUN_MTU?gwmtu:TUN_MTU))

    ip tuntap add dev $TUNIF mode tun
    if [ $? != 0 ]; then
        echo "creat $TUNIF failed, nothing to do!"
        return 1
    fi
    ip link set $TUNIF up
    ip link set $TUNIF mtu $TUN_MTU
    ip addr add $TUN_IP/$TUN_MASK dev $TUNIF

    if [ client == $MODE ]; then
        default_gw_ip=`ip route show | grep '^default' | sed -e 's/.*via \([^ ]*\).*/\1/'`
        if check_ip_format $default_gw_ip; then
            echo $default_gw_ip > $BACKUP_GW_IP
        else
            echo "****!!! no default route found in routing table !!!****"
        fi

        default_gw_ip=`cat $BACKUP_GW_IP`
        check_ip_format $default_gw_ip
        if [ $? != 0 ]; then 
            echo "******!!!!!! default route lost !!!!!!******"
        fi
 
        ip route del default #table main
        #ip route add default dev $TUNIF table default
        ip route add default via $TUN_GW table default
        ip route add $SERVER_ADDR/32 via $default_gw_ip table default
        ip route add $DNS_ADDR_LOCAL/32 via $default_gw_ip table default
    fi

    nohup $EXE_PATH/$EXE_NAME -k $KEY_MD5 -g $GROUP -n $SELF_ID -c $SERVER_ADDR -p $SERVER_PORT -i $TUNIF  >> $LOGFILE &
    sleep 0.1
    ps aux | grep $! | grep -v grep > /dev/null
    if [ $? == 0 ]; then
        cp -f $0 $BACKUP_SCRIPT > /dev/null
        cp -f $CONF_FILE $BACKUP_CONF > /dev/null
        ifconfig $TUNIF | grep inet | awk '{print $2"\t"$NF}'
        echo "client's tunnel MTU is: $TUN_MTU."
        echo "$EXE_NAME started with $TUNIF. connecting to $SERVER_ADDR:$SERVER_PORT"
        return 0
    else
        cat $LOGFILE | tail -n 1
        clientdown
        echo "$EXE_NAME failed to start with $TUNIF!"
        return 1
    fi
}

clientdown()
{
    iplist=`ip addr show | grep inet | awk '{print $2}' | awk -F/ '{print $1}'`
    for ipadd in $iplist; do
        if [ $SERVER_ADDR == $ipadd ]; then
            echo "this is server, nothing to do!"
            return 0
        fi
    done

    check_tun_name $TUNIF
    if [ $? == 0 ]; then
        echo "no $TUNIF anymore, nothing to do!"
        return 0
    fi

    check_ip_format $SERVER_ADDR
    if [ $? != 0 ]; then
        SERVER_ADDR=`ps aux | grep $TUNIF | grep -v grep | sed -e 's/.*-c \([^ ]*\).*/\1/'`
        if [ x$SERVER_ADDR == x"" ]; then
            echo "server address not valid, you may need to delete route manually."
        fi
    fi

    search_instance client
    if [ $? == 0 ]; then
        echo "Warning: no client instance running anymore!"
    else
        kill_tunnel $TUNIF
        if [ $? == 1 ]; then
            echo "$EXE_NAME failed to exit with $TUNIF."
            return 1
        fi
    fi

    if [ client == $MODE ]; then
        default_gw_ip=`cat $BACKUP_GW_IP`
        check_ip_format $default_gw_ip
        if [ $? != 0 ]; then 
            echo "******!!!!!! default route lost !!!!!!******"
        fi

        ip route del default table default
        ip route del $SERVER_ADDR/32 table default
        ip route del $DNS_ADDR_LOCAL/32 table default
        ip route add default via $default_gw_ip
    fi

    ip tuntap del dev $TUNIF mode tun
    if [ $? != 0 ]; then
        echo "delete $TUNIF failed!"
        echo "$EXE_NAME failed to exit with $TUNIF."
        return 1
    fi
    rm -rf $BACKUP_PATH > /dev/null
    echo "$EXE_NAME exited with $TUNIF."
    return 0
}

search_instance()
{
    local mode=$1
    servernr=`ps aux | grep $TUN_PREFIX | grep -v grep | grep -v $BACKUP_PREFIX | grep -e "-s" | wc -l`
    clientnr=`ps aux | grep $TUN_PREFIX | grep -v grep | grep -v $BACKUP_PREFIX | grep -e "-c" | wc -l`

    tunnr=$((servernr+clientnr))
    if [ $tunnr == 0 ]; then
        echo "no instance running!"
        return $tunnr
    fi

    echo "there are $servernr servers and $clientnr clients running!"

    tunlist=`ifconfig | grep $TUN_PREFIX | awk '{print $1}'`
    if [ x$mode != xclient ]; then
        for tunif in $tunlist; do
            listenport=`ps -ef | grep $tunif | grep -v $BACKUP_PREFIX | grep -v grep | sed -e 's/.*-p \([^ ]*\).*/\1/'`
            ps -ef | grep $tunif | grep -v grep | grep -v $BACKUP_PREFIX | grep -e "-s" > /dev/null
            if [ $? == 0 ]; then
                #there's something wrong...why executed when nothing found? and \t should be replaced.
                printf "%s\t%s\t\t%s\t%s\n" $tunif `ifconfig $tunif | grep inet | \
                awk '{print $2" "$4}'` "listening on $listenport"
            fi
        done
    fi

    if [ x$mode != xserver ]; then
        for tunif in $tunlist; do
            serveraddr=`ps -ef | grep $tunif | grep -v $BACKUP_PREFIX | grep -v grep | sed -e 's/.*-c \([^ ]*\).*/\1/'`
            serverport=`ps -ef | grep $tunif | grep -v $BACKUP_PREFIX | grep -v grep | sed -e 's/.*-p \([^ ]*\).*/\1/'`
            ps -ef | grep $tunif | grep -v grep | grep -v $BACKUP_PREFIX | grep -e "-c" > /dev/null
            if [ $? == 0 ]; then
                printf "%s\t%s\t\t%s\t%s\n" $tunif `ifconfig $tunif | grep inet | \
                awk '{print $2" "$4}'` "connecting to $serveraddr:$serverport"
            fi
        done
    fi

    [ x$mode == xserver ] && return $servernr
    [ x$mode == xclient ] && return $clientnr

    return $tunnr
}


case $1 in
start|u|up) 
    if [ $MODE == client ] || [ $MODE == middle_client ]; then
        clientup
    elif [ $MODE == server ] || [ $MODE == middle_server ]; then
        serverup
    else
        echo "wrong MODE! check your configuration."
    fi ;;
stop|d|do|dow|down)
    if [ $MODE == client ] || [ $MODE == middle_client ]; then
        clientdown
    elif [ $MODE == server ] || [ $MODE == middle_server ]; then
        serverdown
    else
        echo "wrong MODE! check your configuration."
    fi ;;
status|s|se|sea|sear|searc|search)
    case $2 in
        s|se|ser|serv|serve|server)
            search_instance server ;;
        c|cl|cli|clie|clien|client)
            search_instance client ;;
        *)
            search_instance ;;
    esac ;;
*) 
    usage ;;
esac

