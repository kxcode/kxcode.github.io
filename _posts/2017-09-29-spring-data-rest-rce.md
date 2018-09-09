---
layout: post
title: Spring Data Rest远程代码执行unpublish
description: "Vulnerability - Java Struts2 S2-052 and XStream"
tags: [Vulnerability,Java,Struts2,漏洞分析]
image:
  background: triangular.png
---

# 0. 概述

官方公告：
https://pivotal.io/security/cve-2017-8046
CNVD安全公告：
http://www.cnvd.org.cn/webinfo/show/4247

分析文章：
https://mp.weixin.qq.com/s/uTiWDsPKEjTkN6z9QNLtSA

影响范围：
Spring Data REST versions prior to 2.5.12, 2.6.7, 3.0 RC3
Spring Boot versions prior to 2.0.0M4
Spring Data release trains prior to Kay-RC3


安全版本下载：
https://github.com/spring-projects/spring-data-rest/releases/tag/2.6.7.RELEASE


POC：
https://github.com/Medicean/VulApps/tree/master/s/spring/1

