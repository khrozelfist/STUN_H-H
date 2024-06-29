# 以下变量需按要求填写
PROXY='socks5://192.168.1.168:10808'		# 可用的代理协议、地址与端口
IFNAME=						# 指定接口，可留空；仅在多 WAN 时需要；拨号接口的格式为 "pppoe-wancm"
HATHDIR=/mnt/hath				# H@H 所在目录
HATHCID=12345					# H@H 的客户端 ID
EHIPBID=1234567					# ipb_member_id
EHIPBPW=0123456789abcdef0123456789abcdef	# ipb_pass_hash
GWLADDR=192.168.1.1				# 主路由 LAN 的 IPv4 地址

WANADDR=$1
WANPORT=$2
LANPORT=$4
L4PROTO=$5
OWNADDR=$6

OWNNAME=$(echo $0 | awk -F / '{print$NF}' | awk -F . '{print$1}')
OLDPORT=$(awk -F ':| ' '{print$3}' $HATHDIR/$OWNNAME.info 2>/dev/null)
OLDDATE=$(awk '{print$NF}' $HATHDIR/$OWNNAME.info 2>/dev/null)
RELEASE=$(grep ^ID= /etc/os-release | awk -F '=' '{print$2}' | tr -d \")

# 防止脚本重复运行
PIDNF=$( ( ps aux 2>/dev/null; ps ) | awk '{for(i=1;i<=NF;i++)if($i=="PID")n=i}NR==1{print n}' )
while :; do
  ( ps aux 2>/dev/null; ps ) | grep $0 | grep -v -e "$$\|grep" | awk 'NR==1{print$'$PIDNF'}' | xargs kill >/dev/null 2>&1 || break
done

# 保存穿透信息
echo $L4PROTO $WANADDR:$WANPORT '->' $OWNADDR:$LANPORT $(date +%s) >$HATHDIR/$OWNNAME.info
echo $(date) $L4PROTO $WANADDR:$WANPORT '->' $OWNADDR:$LANPORT >>$HATHDIR/$OWNNAME.log

# 确保与上次穿透相隔 30 秒以上
[ -n "$OLDDATE" ] && \
[ $(($(date +%s) - $OLDDATE)) -lt 30 ] && sleep 30

# 获取 H@H 设置信息
HATHPHP=/tmp/$OWNNAME.php
touch $HATHPHP
curl -s -m 5 \
-x $PROXY \
-b 'ipb_member_id='$EHIPBID'; ipb_pass_hash='$EHIPBPW'' \
-o $HATHPHP \
'https://e-hentai.org/hentaiathome.php?cid='$HATHCID'&act=settings'
f_cname=$(grep f_cname $HATHPHP | awk -F '"' '{print$6}' | sed 's/[ ]/+/g')
f_throttle_KB=$(grep f_throttle_KB $HATHPHP | awk -F '"' '{print$6}')
f_disklimit_GB=$(grep f_disklimit_GB $HATHPHP | awk -F '"' '{print$6}')
p_mthbwcap=$(grep p_mthbwcap $HATHPHP | awk -F '"' '{print$6}')
f_diskremaining_MB=$(grep f_diskremaining_MB $HATHPHP | awk -F '"' '{print$6}')
f_enable_bwm=$(grep f_enable_bwm $HATHPHP | grep checked)
f_disable_logging=$(grep f_disable_logging $HATHPHP | grep checked)
f_use_less_memory=$(grep f_use_less_memory $HATHPHP | grep checked)
f_is_hathdler=$(grep f_is_hathdler $HATHPHP | grep checked)

# 停止 H@H，等待 30 秒
if [ "$(screen -list | grep $OWNNAME)" ]; then
	screen -S $OWNNAME -X stuff '^C'
	sleep 30
fi

# 更新 H@H 端口信息
DATA="settings=1&f_port=$WANPORT&f_cname=$f_cname&f_throttle_KB=$f_throttle_KB&f_disklimit_GB=$f_disklimit_GB"
[ "$p_mthbwcap" = 0 ] || DATA="$DATA&p_mthbwcap=$p_mthbwcap"
[ "$f_diskremaining_MB" = 0 ] || DATA="$DATA&f_diskremaining_MB=$f_diskremaining_MB"
[ -n "$f_enable_bwm" ] && DATA="$DATA&f_enable_bwm=on"
[ -n "$f_disable_logging" ] && DATA="$DATA&f_disable_logging=on"
[ -n "$f_use_less_memory" ] && DATA="$DATA&f_use_less_memory=on"
[ -n "$f_is_hathdler" ] && DATA="$DATA&f_is_hathdler=on"
curl -s -m 5 \
-x $PROXY \
-b 'ipb_member_id='$EHIPBID'; ipb_pass_hash='$EHIPBPW'' \
-o $HATHPHP \
-d ''$DATA'' \
'https://e-hentai.org/hentaiathome.php?cid='$HATHCID'&act=settings'
[ "$(grep f_port $HATHPHP | awk -F '"' '{print$6}')" = $WANPORT ] || \
echo Failed to get response. Please check PROXY. >&2

# 若 H@H 运行在主路由上，则添加 DNAT 规则
# 系统为 OpenWrt，且未指定 IFNAME 时，使用 uci
# 其他情况使用 nft，并检测是否需要填充 uci
SETDNAT() {
	if [ "$RELEASE" = "openwrt" ] && [ -z "$IFNAME" ]; then
		nft delete chain ip STUN HATHDNAT 2>/dev/null
		uci -q delete firewall.STUN_foo
		uci -q delete firewall.HATHDNAT
		uci set firewall.HATHDNAT=redirect
		uci set firewall.HATHDNAT.name=HATH_$LANPORT'->'$WANPORT
		uci set firewall.HATHDNAT.src=wan
		uci set firewall.HATHDNAT.proto=tcp
		uci set firewall.HATHDNAT.src_dport=$LANPORT
		uci set firewall.HATHDNAT.dest_port=$WANPORT
		uci commit firewall
		fw4 -q reload
		UCI=1
	else
		[ -n "$IFNAME" ] && IIFNAME="iifname $IFNAME"
		nft add table ip STUN
		nft add chain ip STUN HATHDNAT { type nat hook prerouting priority dstnat \; }
		for HANDLE in $(nft -a list chain ip STUN HATHDNAT | grep \"$OWNNAME\" | awk '{print$NF}'); do
			nft delete rule ip STUN HATHDNAT handle $HANDLE
		done
		nft add rule ip STUN HATHDNAT $IIFNAME tcp dport $LANPORT counter redirect to :$WANPORT comment $OWNNAME
	fi
	if [ "$RELEASE" = "openwrt" ] && [ "$UCI" != 1 ]; then
		uci -q delete firewall.STUN_foo && RELOAD=1
		uci -q delete firewall.HATHDNAT && RELOAD=1
		if uci show firewall | grep =redirect >/dev/null; then
			i=0
			for CONFIG in $(uci show firewall | grep =redirect | awk -F = '{print$1}'); do
				[ "$(uci -q get $CONFIG.enabled)" = 0 ] && let i++
			done
			[ $(uci show firewall | grep =redirect | wc -l) -gt $i ] && RULE=1
		fi
		if [ "$RULE" != 1 ]; then
			uci set firewall.STUN_foo=redirect
			uci set firewall.STUN_foo.name=STUN_foo
			uci set firewall.STUN_foo.src=wan
			uci set firewall.STUN_foo.mark=$RANDOM
			RELOAD=1
		fi
		uci commit firewall
		[ "$RELOAD" = 1 ] && fw4 -q reload
	fi
	DNAT=1
}
for LANADDR in $(ip -4 a show dev br-lan | grep inet | awk '{print$2}' | awk -F '/' '{print$1}'); do
	[ "$DNAT" = 1 ] && break
	[ "$LANADDR" = $GWLADDR ] && SETDNAT
done
for LANADDR in $(nslookup -type=A $HOSTNAME | grep Address | grep -v :53 | awk '{print$2}'); do
	[ "$DNAT" = 1 ] && break
	[ "$LANADDR" = $GWLADDR ] && SETDNAT
done

# 若 H@H 运行在主路由下，则通过 UPnP 请求规则
if [ "$DNAT" != 1 ]; then
	nft delete chain ip STUN HATHDNAT 2>/dev/null
	[ "$RELEASE" = "openwrt" ] && uci -q delete firewall.HATHDNAT
	[ -n "$OLDPORT" ] && upnpc -i -d $OLDPORT tcp
	upnpc -i -e "STUN HATH $WANPORT->$LANPORT->$WANPORT" -a @ $WANPORT $LANPORT tcp
fi

# 启动 H@H
RUNHATH() {
for PID in $(screen -ls | grep $OWNNAME | awk '{print$1}'); do
	screen -S $PID -X quit
done
cd $HATHDIR
HATHLOG=/tmp/screen_$OWNNAME.log
: >$HATHLOG
screen -dmS $OWNNAME -L -Logfile $HATHLOG java -jar $HATHDIR/HentaiAtHome.jar
}
RUNHATH

# 检测启动结果
while :; do
	sleep 60
	grep "Startup notification failed" $HATHLOG || { screen -S $OWNNAME -X log off; exit; }
	if grep "port $WANPORT" $HATHLOG; then
		sleep 300
		RUNHATH
	else
		sleep 600
		exec "$0" "$@"
	fi
done
