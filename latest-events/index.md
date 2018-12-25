---
layout: page
title: Latest Security Incidents
description: "Latest Security Incidents"
image:
  feature: abstract-11.jpg
share: true
---

2018
---
1. **【20181214】供应链攻击：驱动人生升级通道被攻击，软件携带后门病毒**
    - <https://www.freebuf.com/vuls/192014.html>
    - 一场精心策划的针对驱动人生公司的定向攻<https://www.freebuf.com/articles/system/192194.html>
    
1. **【20181127】供应链攻击：JavaScript公共库event-stream被植入恶意代码**
    - <https://cert.360.cn/warning/detail?id=00e13636ea1705250545e370bbd8b539>
    - 恶意依赖已经存在了2.5个月内未被发现
    - <https://mp.weixin.qq.com/s/IaOWxG0XLvn2znvvP1dmwA>
    - 相关的Github Issues: <https://github.com/dominictarr/event-stream/issues/115><https://github.com/dominictarr/event-stream/issues/116>
    - 详细介绍：<https://snyk.io/blog/malicious-code-found-in-npm-package-event-stream>
    - 恶意的commit: <https://github.com/dominictarr/event-stream/commit/e3163361fed01384c986b9b4c18feb1fc42b8285>
    - 影响范围：如果你的项目使用了加密货币相关的库并且当你运行命令npm ls event-stream flatmap-stream后你可以看到flatmap-stream@0.1.1，你很可能就受影响了
    - 减轻方案：Downgrade to event-stream@3.3.4
    - 受影响版本：event-stream@3.3.6 (目前已知) 或者 flatmap-stream@any

1. **【20180828】华住大量开房信息泄露**

1. **【20180817】APT DarkHotel**
    - 利用CVE-2018-8373 0day漏洞的攻击与Darkhotel团伙相关的分析<https://ti.360.net/blog/articles/analyzing-attack-of-cve-2018-8373-and-darkhotel/>

1. **【20180712】Carbanak APT团伙恶意木马源码泄露**
    - <http://mal4all.com/showthread.php?tid=494&action=lastpost>
    - https://files.fm/u/t25ymgfm 
    - https://ufile.io/x7412 
    - http://transfiles.ru/lhjmn 
    - https://dropmefiles.com/CnwWE 
    - http://mega.dp.ua/file? source = 18070615225769991162

1. **【20180709】Bancor交易所入侵**
    - <https://bcsec.org/index/detail?id=195&tag=1>

1. **【20180707】币安API再次出现事故，SYSCoin被高价卖出**
    - <https://bcsec.org/index/detail?id=186&tag=2>

1. **【20180619】Docker供应链攻击，攻击者如何利用现代容器化趋势获益**
    - 分析：<https://kromtech.com/blog/security-center/cryptojacking-invades-cloud-how-modern-containerization-trend-is-exploited-by-attackers>
    - 新闻：被下载500万次后 Docker Hub终于撤下了后门镜像<https://www.cnbeta.com/articles/tech/737509.htm>
    
1. **【20180613】Acfun被黑客攻击，数据泄露，暗网售卖**
    - 数据样品：<https://github.com/SakuraKisser/AC_300fun>
    - 官方公告：<http://www.acfun.cn/a/ac4405547>
    - 暗网帖子：<http://lei6ezsexd4iq2tm.onion/viewtopic.php?f=37&t=4545>

1. **【20180524】VPNFilter 新型IoT、网络设备僵尸网络，已感染超过50万台**
    - 报告：<https://blog.talosintelligence.com/2018/05/VPNFilter.html>
    - 分析：VPNFilter-新型IoTBotnet深度解析<https://mp.weixin.qq.com/s/SnchceLdNX7JYiWfSH2Hmw>

1. **【20180524】BTG（Bitcoin Gold） 51%攻击**
    - 报道：<https://www.bleepingcomputer.com/news/security/hacker-makes-over-18-million-in-double-spend-attack-on-bitcoin-gold-network/>

1. **【20180509】百度软件中心putty污染**
    - 分析：<https://m.threatbook.cn/detail/499?from=timeline&isappinstalled=0>
    
1. **【20180423】BEC美链整型溢出漏洞蒸发60亿**
    - 分析：<https://zhuanlan.zhihu.com/p/35989258?>
    - 描述：转账时转账总额存在整型溢出漏洞。攻击者同时转给两个人，转账总金额超过uint256取值范围，溢出为0，绕过了余额校验逻辑。而接收方每个人获得了大量BEC。
    - 分析：[BEC漏洞复盘](https://mp.weixin.qq.com/s?__biz=MzA5MzkwOTgxNg==&mid=2448102023&idx=1&sn=170a474563fe529f9e34b2484cc10bc0&chksm=844914d0b33e9dc686859ef4d0e64456ea5ea1d6710c5de23dd4ebeaa2823096dff577587fc3&mpshare=1&scene=1&srcid=0423SJCIe5iwvrkgwcHLjwLO&rd2werd=1#wechat_redirect)
    - 解析：<http://www.freebuf.com/vuls/169741.html>
    - 报道：[BEC、SMT现重大漏洞，这8个智能合约也可能凉凉](https://mp.weixin.qq.com/s?__biz=MjM5MzEwMzIxMA==&mid=2653192606&idx=1&sn=11a066f4335943dce0459ca5dd26d95c&chksm=bd4c0d9b8a3b848d599e131a1c22da6704281c11b8ce546bb6322b437ad20d674c9328d1c612&mpshare=1&scene=1&srcid=04251KjkUxjVdIk74d5aIx7X%23rd)

1. **【20180402】1.5亿MyFitnessPal用户的数据被泄漏**
    - 报道：http://www.4hou.com/info/news/10939.html
    - vk.com泄露数据：https://mega.nz/#!NSRFDQiR!cSH1YObNiwUAptH7oqzcFi-Zh5Qij7xO1F1Eh87KFQs

1. **【20180320】Facebook用户好友关系泄露**
    - 卫报报道：<https://www.theguardian.com/technology/2018/mar/17/facebook-cambridge-analytica-kogan-data-algorithm>
    - <https://mp.weixin.qq.com/s/v9daFF0ZTuHBp-PwteDd0Q>
    - 描述：这个应用在要求用户使用Facebook账号登录，给用户 2-5 美元来完成一个调查，同时获取你的好友关系并且查看你点赞了哪些东西，通过调查和你点赞的数据来给你画像，判断你对什么感兴趣，然后以此可以给你更精准的广告信息。
    - 扎克伯格回应: <https://www.facebook.com/zuck/posts/10104712037900071>
    - <http://url.cn/5ic0R1C>

1. **【20180307】币安API Key被攻击**
    - 用Unicode的币安域名，底部有两个点，类似于ẹ字符。
    - <https://mp.weixin.qq.com/s/z39hBMif1bQJeb4Ar_zRAw>
    - <http://36kr.com/p/5122966.html>
    - https://steemit.com/eos/@whynot/how-to-newest-phishing-sites-e-g-eos-binance-how-to-protect-yourself

1. **【20180120】一加称 4 万客户的信用卡信息泄露**
    - <https://www.solidot.org/story?sid=55280>


2017
---
1. **【201711】macOS High Sierra Root账户空口令漏洞**
    - <http://soft.hqbpc.com/html/2017/11/60928.html>


1. **【201709】PyPI 官方库被发现混入了名字相似的恶意模块**
    - http://www.solidot.org/story?sid=53867


1. **【201709】Equifax数据泄露事件致CIO和CISO离职**
    - Struts2
    - 2018年12月发布细节，<https://oversight.house.gov/wp-content/uploads/2018/12/Equifax-Report.pdf>

1. **【201708】 XSHELL 后门植入**