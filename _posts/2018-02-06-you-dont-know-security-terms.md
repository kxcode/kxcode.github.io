---
layout: post
title: 你不知道的安全行业术语 - 持续更新
description: "security"
tags: [security,community]
image:
  background: triangular.png
---


Adversary Emulation
---
敌对模拟

OSINT
---
Open Source Intelligence - 公开资源情报

DREAD
---
威胁建模
http://onlinehelp.microsoft.com/zh-cn/mdop/ff648644.aspx

HUMINT
---
人员情报

PHF
---	
Potential Harmful Features - 潜在有害特征

IDOR
---
Insecure Direct Object Reference - 不安全的对象直接引用

约等于通常所说的越权漏洞

1337语言
---
a -> 4

RPO
---
Relative Path Overwrite - 相对路径覆盖

比如2018年第二届强网杯CTF中的RPO XSS题目。构造如下链接：

    http://39.107.33.96:20000/index.php/view/article/23049/..%2f..%2f..%2f..%2findex.php

PHP接收到的是URL解码后的参数，Apache和Nginx会按照目录的方式来返回我们请求的资源，最终返回网站首页。

    http://39.107.33.96:20000/index.php/view/article/23049/../../../../index.php
    =>
    http://39.107.33.96:20000/

但是浏览器在解析HTML页面上的相对路径资源内容时，没有将%2f进行URL解码，所以HTML页面中引用到的JS文件路径为：

    http://39.107.33.96:20000/index.php/view/article/23049/..%2f..%2f..%2f..%2findex.php/static/js/jquery.min.js

由于Apache URL Rewrite相关配置，这个链接返回的内容实际上是`http://39.107.33.96:20000/index.php/view/article/23049`的内容。而`http://39.107.33.96:20000/index.php/view/article/23049`内容时我们插入的恶意文章，被浏览器当成JS解析了，造成XSS。

Compromised
---
攻陷

Breach
---
(数据)泄露

Living Off The Land Techniques
---
一种使用系统默认程序、组件来绕过主机检测，隐藏恶意软件真实目的，进行命令执行、上传下载、编译、植入后门等操作的一种技术。
常见的分类有：LOL Binaries、LOL Libs、LOL Scripts。

VPC
---
Virtual Private Cloud 虚拟私有云

SAST / DAST
---
Static Application Security Testing / Dynamic Application Security Testing

更多相关术语：<https://www.gartner.com/it-glossary/>




