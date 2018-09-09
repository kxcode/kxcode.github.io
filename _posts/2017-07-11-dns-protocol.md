---
layout: post
title: DNS协议
description: "DNS Protocol"
tags: [protocol]
image:
  background: triangular.png
---

# 0x01 前言

RFC1035文档：<https://tools.ietf.org/html/rfc1035>

使用DNS作为RESTWeb服务的发现机制
https://www.oschina.net/translate/rest-discovery-dns?print

DNS协议分析
http://www.cnblogs.com/549294286/p/5172448.html

一些DNS介绍也可以参考这个论文
http://www.docin.com/p-1127048201.html

顶级域名：
https://www.iana.org/domains/root/db

## 名词说明
**LABEL** - 域名中的每一节,如：label.label.label 。

允许的字符范围为：字母、-、数字。Tips: 有些例外，比如DNS发现服务的PTR中会包含下划线，如: _udp.C
			
**NAMES** - 域名名称。

**MESSAGE** - DNS消息数据包，如请求包、响应包等。

**RR** - ResourceRecord(资源记录)，表示一条DNS记录。在DNS消息数据包中，有多处会包含RR记录。比如：响应类型的DNS消息数据包中Answer部分，包含了多个ResourceRecord资源记录，作为对DNS请求中的问题的回答。

## 大小限制
一些对象和参数在DNS中存在大小限制。如下：

    labels          63 octets or less			
    names           255 octets or less
    TTL             positive values of a signed 32 bit number.
    UDP messages    512 octets or less

# 0x02 Domain Name Space 和 RR 的定义

## Name Space
域名均使用一个label序列来表示，如：xxx.yyy.com。每个label最前面，会有一个八位字节来表示这个label的长度，如：xxx表示为 3xxx。每个域名都以空label结束，也就是使用一个值为0的长度字节为终结。表示长度的八位字节，前两位必须为0，剩下只有6位，这样就限制了每个label最大长度为63个字节。

简单实现下，域名的总长度（label字节 和 表示label长度的字节）限制为最多255个字节。

虽然label可以包含任意8bit的值，但还是强烈建议使用本文中推荐的语法，来兼容现有的主机命名约定。

## RR的定义（Resource Record）

### 格式

```
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                                               /
/                      NAME                     /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     CLASS                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TTL                      |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   RDLENGTH                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
/                     RDATA                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```


| 字段 	 	| 说明							|
| --------- | --------						|
| NAME     	| an owner name, i.e., the name of the node to which this resource record pertains.|
| TYPE     	| 两个八位字节				|
| CLASS    	| 两个八位字节				|
| TTL      	| 32位有符号整型				|
| RDLENGTH 	| 无符号16位整型。表示了RDATA的长度。|
| RDATA    	| 可变长度的资源描述字符串。这个信息的格式，随着ResourceRecord的TYPE和CLASS而变化。|



### TYPE 取值范围
TYPE字段出现在ResourceRecord记录中。 这些类型是QTYPEs的一个子集。

```
TYPE            value and meaning
A               1 a host address
NS              2 an authoritative name server
MD              3 a mail destination (Obsolete - use MX)
MF              4 a mail forwarder (Obsolete - use MX)
CNAME           5 the canonical name for an alias
SOA             6 marks the start of a zone of authority
MB              7 a mailbox domain name (EXPERIMENTAL)
MG              8 a mail group member (EXPERIMENTAL)
MR              9 a mail rename domain name (EXPERIMENTAL)
NULL            10 a null RR (EXPERIMENTAL)
WKS             11 a well known service description
PTR             12 引导至一个规范名称（Canonical Name）。与 CNAME 记录不同，DNS“不会”进行进程，只会传回名称。最常用来运行反向 DNS 查找，其他用途包括引作 DNS-SD
HINFO           13 host information
MINFO           14 mailbox or mail list information
MX              15 mail exchange
TXT             16 text strings

AFSDB			18 （Andrew File System）数据库核心的位置，于域名以外的 AFS 客户端常用来联系 AFS 核心。这个记录的子类型是被过时的的 DCE/DFS（DCE Distributed File System）所使用。
AAAA			28 传回一个 128 比特的 IPv6 地址，最常用于映射主机名称到 IP 地址
SRV             33 Server Selection
APL 			42 指定地址列表的范围，例如：CIDR 格式为各个类型的地址（试验性）。
```

### QTYPE 取值范围

QTYPE字段出现在DNS请求的Question部分。QTYPES是TYPEs的超集。另外, 还定义了如下QTYPEs:

```
AXFR            252 A request for a transfer of an entire zone
MAILB           253 A request for mailbox-related records (MB, MG or MR)
MAILA           254 A request for mail agent RRs (Obsolete - see MX)
*               255 A request for all records
```


### CLASS 取值范围

CLASS字段出现在ResourceRecord记录中，定义了如下CLASS的助记符和值:

```
IN              1 the Internet
CS              2 the CSNET class (Obsolete - used only for examples in
                some obsolete RFCs)
CH              3 the CHAOS class
HS              4 Hesiod [Dyer 87]
```

### QCLASS 取值范围

QCLASS字段出现在请求的Question部分中。QCLASS是CLASS的超集。除了合法的CLASS取值之外，QCLASS还定义了如下值:

```
*               255 any class
```



# 0x03 Message

## Message 格式

所有DNS协议的通信都包含在message格式中[^1]。message的顶层结构分为5个部分。某些情况下，有的部分可以为空。

```
+---------------------+
|        Header       |
+---------------------+
|       Question      | the question for the name server
+---------------------+
|        Answer       | RRs answering the question
+---------------------+
|      Authority      | RRs pointing toward an authority
+---------------------+
|      Additional     | RRs holding additional information
+---------------------+
```

Header部分为必须结构，Header中也指定了消息中包含了剩下的哪几部分。并指定了消息类型（请求还是响应、标准请求或者其他opcode）。

Question部分包含了向NameServer请求的问题描述，这些描述字段有：请求类型 (QTYPE), 请求 class (QCLASS), 请求域名 (QNAME)。

剩下三个部分结构相同：多个RR（Resource Record）连接组成的列表（可能为空）。

1. Answer 部分包含了针对请求问题的响应内容，同样为一个或多个RR记录组成的列表。
2. Authority 部分包含了RR记录指向权威的NS域名服务器。
3. Additional 部分包含了与请求相关答案的RR记录，但这不是严格的答案。


## Question 格式

Question部分用来承载DNS请求中的问题内容。这个部分包含 QDCOUNT 项（QDCOUNT在Message的Header中，通常为1）, 每一项的格式为：


```
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

字段			|	说明
---			|	---
QNAME       |    a domain name represented as a sequence of labels, where each label consists of a length octet followed by that number of octets.  The domain name terminates with the zero length octet for the null label of the root.  Note that this field may be an odd number of octets; no padding is used.
QTYPE       |    a two octet code which specifies the type of the query.The values for this field include all codes valid for a TYPE field, together with some more general codes which can match more than one type of RR.
QCLASS      |    a two octet code that specifies the class of the query.For example, the QCLASS field is IN for the Internet.

## Answer

一个响应包含多条内容，如响应多个IPv6地址。
问题为A请求，响应中也可能是多种其他类型的响应记录。

# 0x04 域名命名

顶级域 TLD Top-level Domain

顶级域主要分4类：

- 国家及地区顶级域
- 通用顶级域
- 基础建设顶级域（.arpa<以美国军方arpa网命名>，过去曾包括在“通用顶级域”内）
    1987年RFC1034
    2000年arpa被重新定义为：Address and Routing Parameter Area
- 测试顶级域（例如繁体的 http://例子.测试/ 及简体的 http://例子.测试/

https://www.zhihu.com/question/21310402

顶级域名：
https://www.iana.org/domains/root/db

# 0x05 DNS反向解析 - arpa

https://stackoverflow.com/questions/23981098/how-forward-and-reverse-dns-works

infrastructure top-level domain
基础建设顶级域（.arpa<以美国军方arpa网命名>，过去曾包括在“通用顶级域”内）
    1987年RFC1034
    2000年arpa被重新定义为：Address and Routing Parameter Area

arpa also contains the domains for reverse domain name resolution in-addr.arpa and ip6.arpa for IPv4 and IPv6, respectively.

# 0x06 Public Suffix List
https://publicsuffix.org/list/public_suffix_list.dat

# 0x07 akadns.net 等一系列DNS负载均衡？
https://answers.yahoo.com/question/index?qid=20060806160840AAykHcT
https://en.wikipedia.org/wiki/Load_balancing_%28computing%29

# 0x07 服务发现

使用DNS作为RESTWeb服务的发现机制
https://www.oschina.net/translate/rest-discovery-dns?print    

# Reference
[^1]: http://www.cnblogs.com/pied/p/3571055.html                