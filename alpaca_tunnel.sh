#!/bin/bash
export PATH="/bin:/sbin:/usr/sbin:/usr/bin:/usr/local/bin"


EXE_NAME=AlpacaTunnel
TUN_PREFIX=alptun
TUN_MASK=16
HEADER_LEN=60  #20+8+32, IP+UDP+AlpacaHeader
LOGFILE=/var/log/alpaca_tunnel.log

CUR_DIR=$(cd `dirname $0` && pwd -P)

EXE_PATH=$CUR_DIR
CONF_PATH=$CUR_DIR
if [ $CUR_DIR == "/usr/local/bin" ]; then
    CONF_PATH=/usr/local/etc
elif [ $CUR_DIR == "/usr/bin" ];then
    CONF_PATH=/etc
fi

CONF_FILE=$CONF_PATH/alpaca_tunnel.conf
SECRET_FILE=$CONF_PATH/alpaca_tunnel.d/alpaca_secrets

if [ -r $CONF_FILE ]; then
    source $CONF_FILE
else
    echo "error: configure file not available!"
    exit 1
fi

[ ! "$(ip addr)" ] && echo "The programm ip is not available! Please install it first." && exit 1

TUN_IP=10.$NETID.$SELF_ID
TUN_GW=10.$NETID.$GW_ID
TUNIF=$TUN_PREFIX$TUN_INDEX
BACKUP_PREFIX=running_backup_
BACKUP_PATH=/tmp/running_backup_$TUNIF
mkdir -p $BACKUP_PATH
BACKUP_SCRIPT=$BACKUP_PATH/alpaca_tunnel.sh
BACKUP_CONF=$BACKUP_PATH/alpaca_tunnel.conf
BACKUP_SERVER_LIST_FILE=$BACKUP_PATH/server_list
BACKUP_GW_IP=/$BACKUP_PATH/phy_gw_ip
BACKUP_GW_DEV=/$BACKUP_PATH/phy_gw_dev

TCPMSS=$((TUN_MTU-60))

usage()
{
    #Usage: $EXE_NAME [-s|-c host] [-p port] [-k psk] [-i tun]
    echo "Usage: $0 version|up|down|search"
    return 1
}

check_tun_name()
{
    [ -z $1 ] && return 0
    local tunif=$1
    ip addr | grep -q $tunif
    if [ $? == 0 ]; then
        tunlist=`ip addr | grep $tunif | grep -E "^[0-9]{1,9}" | awk '{print $2}' | awk -F: '{print $1}'`
        for ifname in $tunlist; do 
            if [ $tunif == $ifname ]; then
                return 1   #there is a same tun
            else
                return 2    #there is a tun with the same prefix
            fi
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

    [ ! "$(bc --version)" ] && echo "The programm bc is not available! Please install it first." && exit 1

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

#return 0: exe started
#return 1: exe didn't start
start_exe()
{
    local tunif=$1
    [ "$tunif" == "" ] && echo "start_exe: no tunif specified, nothing to do!" && return 1

    check_tun_name $tunif
    [ $? == 0 ] && echo "start_exe: $tunif don't exists, nothing to do!" && return 1

    [ ! "$($EXE_PATH/$EXE_NAME -v)" ] && \
    echo "start_exe: ELF file $EXE_NAME not available! Please make it first." && return 1

    #TUNIF must be put at the end of the cmd line, for search use.
    stdbuf -i0 -o0 -e0 nohup $EXE_PATH/$EXE_NAME -p $PORT -g $GROUP -n $SELF_ID -i $tunif | tee -a $LOGFILE &
    sleep 0.3
    ps aux | grep $! | grep -v grep > /dev/null
    if [ $? == 0 ]; then
        echo "start_exe: $EXE_NAME started on port $PORT with $tunif."
        return 0
    else
        echo "start_exe: $EXE_NAME failed to start with $tunif!"
        return 1
    fi
}

#return 0: exe stopped
#return 1: exe still exists
stop_exe()
{
    #only kill process bind to $tunif
    local tunif=$1
    [ "$tunif" == "" ] && echo "stop_exe: no tunif specified, nothing to do!" && return 1

    #search_instance $tunif
    #[ $? == 0 ] && echo "warning: cann't find instance of tunnel $tunif, nothing to kill!" && return 0

    #pid=`ps ax | grep $EXE_NAME | awk /-i\ $tunif$/ | awk '{print $1}'`
    pid=`ps ax | grep $EXE_NAME | grep -v grep | grep -e "$tunif$" | awk '{print $1}'`
    [ "$pid" == "" ] && echo "stop_exe: cann't find pid of tunnel $tunif, nothing to kill!" && return 0

    kill $pid
    for t in `seq 2`; do
        ps $pid > /dev/null
        [ $? == 0 ] && sleep $t && kill $pid
    done

    for t in `seq 2`; do
        ps $pid > /dev/null
        [ $? == 0 ] && echo "stop_exe: kill by force!" && sleep $t && kill -9 $pid
    done

    ps $pid > /dev/null
    [ $? == 0 ] && echo "stop_exe: kill $EXE_NAME failed!" && return 1

    return 0
}

#return 0: tunif added or exist an old one
#return 1: tunif didn't add
add_tunif()
{
    local tunif=$1
    [ "$tunif" == "" ] && echo "add_tunif: no tunif specified, nothing to do!" && return 1

    check_tun_name $tunif
    [ $? != 0 ] && echo "add_tunif: $tunif already exists, nothing to do!" && return 0

    ipmasklist=`ip addr show | grep inet | awk '{print $2}'`
    for im in $ipmasklist; do
        check_ip_overlap $im $TUN_IP/$TUN_MASK
        [ $? == 0 ] && echo "add_tunif: tunnel network overlaps with $im, nothing to do!" && return 1
    done

    ip tuntap add dev $tunif mode tun
    [ $? != 0 ] && echo "add_tunif: creat $tunif failed, nothing to do!" && return 1
    ip link set $tunif up
    ip link set $tunif mtu $TUN_MTU
    ip addr add $TUN_IP/$TUN_MASK dev $tunif

    #ip addr show dev $tunif | grep inet | awk '{print "tunnel IP : "$2}'
    #echo "add_tunif: tunnel MTU: $TUN_MTU"
    return 0
}

#return 0: tunif deleted
#return 1: tunif still exists
del_tunif()
{
    local tunif=$1
    [ "$tunif" == "" ] && echo "del_tunif: no tunif specified, nothing to do!" && return 1

    check_tun_name $tunif
    [ $? == 0 ] && echo "del_tunif: no $tunif anymore, nothing to do!" && return 0

    ip tuntap del dev $tunif mode tun
    if [ $? != 0 ]; then
        echo "del_tunif: delete $tunif failed!"
        echo "del_tunif: $EXE_NAME failed to exit with $tunif."
        return 1
    else
        echo "del_tunif: $EXE_NAME exited with $tunif."
        return 0
    fi
}

serverup()
{
    check_tun_name $TUNIF
    [ $? != 0 ] && echo "serverup: $TUNIF already exists, nothing to do!" && return 0

    add_tunif $TUNIF
    [ $? != 0 ] && return 1
    
    #only check main table
    default_gw_dev=`ip route show | grep '^default' | sed -e 's/.*dev \([^ ]*\).*/\1/'`
    if [ "$default_gw_dev" == "" ]; then
        echo "warning: default route lost, will not add iptables rule!"
    else
        echo $default_gw_dev > $BACKUP_GW_DEV
        gwmtu=`ip link show dev $default_gw_dev | grep -i mtu | sed -e 's/.*mtu \([^ ]*\).*/\1/'`
        tunmtu=$((gwmtu-HEADER_LEN))
        [ $tunmtu -lt $TUN_MTU ] && echo "warning: tunnel MTU/TCPMSS may too big!"
        iptables -t nat -A POSTROUTING -s $TUN_IP/$TUN_MASK -o $default_gw_dev -j MASQUERADE
    fi
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    iptables -A FORWARD -p tcp --syn -s $TUN_IP/$TUN_MASK -j TCPMSS --set-mss $TCPMSS
    cp -f $0 $BACKUP_SCRIPT > /dev/null
    cp -f $CONF_FILE $BACKUP_CONF > /dev/null

    #if failed, don't run serverdown, let user to do it.
    start_exe $TUNIF
    [ $? != 0 ] && return 1
    return 0
}

serverdown()
{
    check_tun_name $TUNIF
    [ $? == 0 ] && echo "serverdown: no $TUNIF any more, nothing to do!" && return 0

    stop_exe $TUNIF
    [ $? != 0 ] && return 1

    iptables -D FORWARD -p tcp --syn -s $TUN_IP/$TUN_MASK -j TCPMSS --set-mss $TCPMSS

    default_gw_dev=`cat $BACKUP_GW_DEV`
    [ "$default_gw_dev" != "" ] && iptables -t nat -D POSTROUTING -s $TUN_IP/$TUN_MASK -o $default_gw_dev -j MASQUERADE

    del_tunif $TUNIF
    [ $? != 0 ] && return 1

    rm -rf $BACKUP_PATH > /dev/null
    return 0
}

clientup()
{
    check_ip_format $TUN_GW
    [ $? != 0 ] && echo "clientup: error, NETID or GW_ID may be wrong!" && return 1

    check_tun_name $TUNIF
    [ $? != 0 ] && echo "clientup: $TUNIF already exists, nothing to do!" && return 0

    [ ! -r $SECRET_FILE ] && echo "clientup: error, secret file not available!" && return 1

    add_tunif $TUNIF
    [ $? != 0 ] && return 1

    #must start exe first, then change default to tunif, otherwise exe cann't do nslookup
    start_exe $TUNIF
    [ $? != 0 ] && return 1

    iptables -A FORWARD -p tcp --syn -s $TUN_IP/$TUN_MASK -j TCPMSS --set-mss $TCPMSS
    cp -f $0 $BACKUP_SCRIPT > /dev/null
    cp -f $CONF_FILE $BACKUP_CONF > /dev/null

    iplist=`ip addr show | grep inet | awk '{print $2}' | awk -F/ '{print $1}'`
    server_list=`cat $SECRET_FILE | sed -r "s/^\s+//g" | grep -v -e "^#" | awk '{print $3}' | grep -v -e "^$"`

    for server in $server_list; do
        check_ip_format $server
        if [ $? == 0 ]; then
            echo $server >> $BACKUP_SERVER_LIST_FILE
        else
            ip=`nslookup $server`
            if [ $? != 0 ]; then
                echo "server name $server lookup failed, check your server address."
            else
                server=`echo $ip | awk '{print $NF}'`
                echo $server >> $BACKUP_SERVER_LIST_FILE
            fi
        fi
    done
    server_list=`cat $BACKUP_SERVER_LIST_FILE`

    for server in $server_list; do
        for ip in $iplist; do
            [ $server == $ip ] && echo "warning: check if this is server, don't run client on a server!"
        done
    done

    for server in $server_list; do
        server_gw_dev=`ip route get $server | grep dev | sed -e 's/.*dev \([^ ]*\).*/\1/'`
        [ "$server_gw_dev" == "" ] && echo "warning: no route to server $server"
    done

    #only check main table
    default_gw_ip=`ip route show | grep '^default' | sed -e 's/.*via \([^ ]*\).*/\1/'`
    default_gw_dev=`ip route show | grep '^default' | sed -e 's/.*dev \([^ ]*\).*/\1/'`
    check_ip_format $default_gw_ip
    if [ $? == 0 ]; then
        echo $default_gw_ip > $BACKUP_GW_IP
        echo $default_gw_dev > $BACKUP_GW_DEV
        gwmtu=`ip link show dev $default_gw_dev | grep -i mtu | sed -e 's/.*mtu \([^ ]*\).*/\1/'`
        tunmtu=$((gwmtu-HEADER_LEN))
        [ $tunmtu -lt $TUN_MTU ] && echo "warning: tunnel MTU/TCPMSS may too big!"
    else
        echo "****!!! warning: no default route found in routing table !!!****"
    fi

    default_gw_ip=`cat $BACKUP_GW_IP`
    check_ip_format $default_gw_ip
    if [ $? != 0 ]; then 
        echo "******!!!!!! warning: default route lost !!!!!!******"
    else
        ip route del default #table main
        ip route add default via $TUN_GW table default
        for server in $server_list; do
            ip route add $server/32 via $default_gw_ip table default
        done
        ip route add $DNS_ADDR_CN/32 via $default_gw_ip table default
    fi

    return 0
}

clientdown()
{
    check_tun_name $TUNIF
    [ $? == 0 ] && echo "serverdown: no $TUNIF any more, nothing to do!" && return 0

    stop_exe $TUNIF
    [ $? != 0 ] && return 1

    iptables -D FORWARD -p tcp --syn -s $TUN_IP/$TUN_MASK -j TCPMSS --set-mss $TCPMSS

    [ ! -r $SECRET_FILE ] && echo "clientdown: warning, secret file not available!"
    iplist=`ip addr show | grep inet | awk '{print $2}' | awk -F/ '{print $1}'`
    
    server_list=`cat $BACKUP_SERVER_LIST_FILE`
    #server_list=`cat $SECRET_FILE | sed -r "s/^\s+//g" | grep -v -e "^#" | awk '{print $3}' | grep -v -e "^$"`
    for server in $server_list; do
        for ip in $iplist; do
            [ $server == $ip ] && echo "warning: check if this is server, don't run client on a server!"
        done
    done

    default_gw_ip=`cat $BACKUP_GW_IP`
    check_ip_format $default_gw_ip
    if [ $? != 0 ]; then 
        echo "******!!!!!! warning: default route lost !!!!!!******"
    else
        ip route del default table default
        for server in $server_list; do
            ip route del $server/32 table default
        done
        ip route del $DNS_ADDR_CN/32 table default
        ip route add default via $default_gw_ip
    fi

    del_tunif $TUNIF
    [ $? != 0 ] && return 1

    rm -rf $BACKUP_PATH > /dev/null
    return 0
}

search_instance()
{
    local tunif=$1
    if [ "$tunif" == "" ]; then
        tunnr=`ps aux | grep $EXE_NAME | grep $TUN_PREFIX | grep -v grep | grep -v $BACKUP_PREFIX | wc -l`
    else
        tunnr=`ps aux | grep $EXE_NAME | grep $TUN_PREFIX | grep -e "$tunif$" | grep -v grep | grep -v $BACKUP_PREFIX | wc -l`
    fi

    [ $tunnr == 0 ] && echo "no instance running!" && return 0

    echo "Total running instance: $tunnr"

    tunlist=`ip addr | grep $TUN_PREFIX | grep -v grep | grep -E "^[0-9]{1,9}" | awk '{print $2}' | awk -F: '{print $1}'`

    for tun in $tunlist; do
        pid=`ps aux | grep $EXE_NAME | grep $tun | grep -v grep | awk '{print $2}'`
        port=`netstat -anup | grep $EXE_NAME | grep $pid | awk '{print $4}' | awk -F: '{print $2}'`
        ps -ef | grep -v grep | grep -v $BACKUP_PREFIX | grep -q $tun
        [ $? == 0 ] && printf "%s\t\t%s\t\t%s\n" $tun `ip addr show dev $tun | grep inet | awk '{print $2}'` "port:$port"
    done
    
    return $tunnr
}


case $1 in
version|versio|versi|vers|ver|ve|v)
    version=`$EXE_PATH/$EXE_NAME -v`
    echo $version ;;
start|u|up) 
    if [ $MODE == client ]; then
        clientup
    elif [ $MODE == server ]; then
        serverup
    else
        echo "wrong MODE! check your configuration."
    fi ;;
stop|d|do|dow|down)
    if [ $MODE == client ]; then
        clientdown
    elif [ $MODE == server ]; then
        serverdown
    else
        echo "wrong MODE! check your configuration."
    fi ;;
status|s|se|sea|sear|searc|search)
    search_instance $2 ;;
*) 
    usage ;;
esac

