#########################################################################################################
# 查看谁在用网卡
#########################################################################################################
# using_nvidia_pids=($(nvidia-smi |awk '$3 ~ /^[0-9]+$/ && $1 == "|" {ORS=" "; print $3}'))
# for pid in ${using_nvidia_pids[*]}; do; done
function print_use_gpu_msg() {
	echo 用户 进程id 程序路径 占用显存 # | column -t
	nvidia-smi |awk  '$3 ~ /^[0-9]+$/ && $1 == "|" {print $3,$5,$6}' | while read pid path take_mem
	do
		user=$(ps aux|awk -v p="$pid" '$2 == p {print $1}')
		echo $user $pid $path $take_mem # | column -t
	done
}

print_use_gpu_msg | column -t

#########################################################################################################
# Ubuntu的iptables
#########################################################################################################
#在ubuntu中由于不存在/etc/init.d/iptales文件，所以无法使用service等命令来启动iptables，需要用modprobe命令。
#启动iptables
modprobe ip_tables
#关闭iptables（关闭命令要比启动复杂）
iptables -F
iptables -X
iptables -Z
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
modprobe -r ip_tables
#依次执行以上命令即可关闭iptables，否则在执行modproble -r ip_tables时将会提示
#FATAL: Module ip_tables is in use.


#########################################################################################################
# iptables
#########################################################################################################
# 转发内网端口62701到外网端口62799，改文件/etc/init.d/iptables.up.rules
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [1:60]
:POSTROUTING ACCEPT [0:0]
-A PREROUTING  -d 10.21.76.31/32 -p tcp -m tcp --dport 62799 -j DN
AT --to-destination 11.11.11.1:62701
-A POSTROUTING -j MASQUERADE
COMMI

# 重新加载iptables
iptables-restore < /etc/init.d/iptables.up.rules

*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
COMMIT

#########################################################################################################

#########################################################################################################
