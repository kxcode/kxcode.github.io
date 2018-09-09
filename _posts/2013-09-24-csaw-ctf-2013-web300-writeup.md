---
layout: post
title: CSAW CTF 2013 Web300 Writeup
description: "csaw ctf android web writeup"
modified: 2016-04-06
tags: [android, ctf]
---

面向全球的入门级CSAW CTF 2013比赛已经落幕。

中秋时跟Tony组队玩了一下。感觉好多`reverse`和`exploit`的题目，苦手啊。
这里对其中Web类的300分题目作一个小结。
题目内容是一个apk应用，运行如下图：

![apk]({{ site.url }}/images/articles/201309/0.jpg)

很简单的一个应用，貌似只有一个简单的登录功能。通过查看资源文件，发现了url地址：<https://webchal.isis.poly.edu/csaw.php>

目测就是向这个地址提交登录数据。使用dex2jar反编译该apk,代码没有经过混淆，但是登录的关键类AuthRequest的主要方法无法编译出源码。

于是打开burpsuit，配置模拟器代理，想抓包分析一下登录过程。但是发现apk好像会检测ssl证书的真实性，在模拟器上安装了burpsuit的证书仍然不行，会返回`Unknown Error`的错误信息。查找反编译出来的源码，发现apk中的有个方法会检查SSL证书：

{% highlight java%}
private static class AlwaysTrustManager
  implements X509TrustManager
{
  String C = "C=US";
  String CN1 = "CN=ROOT CA";
  String CN2 = "CN=webchal.isis.poly.edu";
  String L = "L=New York";
  String O1 = "O=Research and Development";
  String O2 = "O=Clandestine Automations Intl";
  String OU = "OU=Black Ops";
  BigInteger SERIAL = new BigInteger("4919");
  String ST = "ST=New York";

  private Boolean isValid(String[] paramArrayOfString1, String[] paramArrayOfString2, BigInteger paramBigInteger)
  {
    if ((paramArrayOfString1[0].equals(this.CN1)) && (paramArrayOfString1[1].equals(this.OU)) && (paramArrayOfString1[2].equals(this.O1)) && (paramArrayOfString1[3].equals(this.O2)) && (paramArrayOfString1[4].equals(this.L)) && (paramArrayOfString1[5].equals(this.ST)) && (paramArrayOfString1[6].equals(this.C)) && (paramArrayOfString2[0].equals(this.CN2)) && (paramArrayOfString2[1].equals(this.OU)) && (paramArrayOfString2[2].equals(this.O1)) && (paramArrayOfString2[3].equals(this.O2)) && (paramArrayOfString2[4].equals(this.ST)) && (paramArrayOfString2[5].equals(this.C)) && (paramBigInteger.equals(this.SERIAL)))
      return Boolean.valueOf(true);
    return Boolean.valueOf(false);
  }
{% endhighlight %}

使用apktool反汇编apk,得到smali源码，找到该方法对应的smali代码：

{% highlight java%}
.method private isValid([Ljava/lang/String;[Ljava/lang/String;Ljava/math/BigInteger;)Ljava/lang/Boolean;
    .locals 7
    .parameter "issuerDN"
    .parameter "subjectDN"
    .parameter "serial"

    .prologue
    const/4 v6, 0x4

    const/4 v5, 0x3

    const/4 v4, 0x2

    const/4 v3, 0x1

    const/4 v2, 0x0

    .line 103
    aget-object v0, p1, v2

    iget-object v1, p0, Lops/black/herpderper/TrustModifier$AlwaysTrustManager;->CN1:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    aget-object v0, p1, v3

    iget-object v1, p0, Lops/black/herpderper/TrustModifier$AlwaysTrustManager;->OU:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    aget-object v0, p1, v4
{% endhighlight%}

与java代码比对，smali代码中，分别将传入的数组中的每个元素与对应的局部变量比较，如果不相等就跳转到:cond_0代码段。

{% highlight java%}
.line 119
invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

move-result-object v0

.line 121
:goto_0
return-object v0

:cond_0
invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

move-result-object v0

goto :goto_0
.end method
{% endhighlight %}

:cond_0代码段就是将v2(也就是false)作为boolean型赋值给v0,然后跳转到:goto_0代码段return v0。如果全部相等则不会跳转直接顺序执行直到:goto_0代码段return v0(此时为true)。这里将:cond_0代码段改为也返回true。即绕过apk中ssl证书的验证。

使用apktool重新构建，autosign给apk签名。使用篡改过的apk登录，可以正常抓包。但是服务端返回Client integrity fault。貌似会检测apk的完整性。查找源代码，登录代码如下：

{% highlight java %}
public class UserLoginTask extends AsyncTask<Void, Void, Boolean>
  {
    public UserLoginTask()
    {
    }

    protected Boolean doInBackground(Void[] paramArrayOfVoid)
    {
      try
      {
        String[] arrayOfString = new String[4];
        arrayOfString[0] = SuperSecretAuthorizationActivity.this.getString(2130968593);
        arrayOfString[1] = SuperSecretAuthorizationActivity.this.mEmail;
        arrayOfString[2] = SuperSecretAuthorizationActivity.this.mPassword;
        arrayOfString[3] = SuperSecretAuthorizationActivity.this.sigChar();
        SuperSecretAuthorizationActivity.this.authreq.execute(arrayOfString);
        SuperSecretAuthorizationActivity.this.setMessage(SuperSecretAuthorizationActivity.this.getString(2130968590));
        Boolean localBoolean = Boolean.valueOf(true);
        return localBoolean;
      }
      catch (Exception localException)
      {
      }
      return Boolean.valueOf(false);
    }

{% endhighlight %}

登录时除了传送email和password外，还会提交应用的signature值。
写了一个小应用来获取apk的签名值，关键代码如下：

{% highlight java %}
public String getSingInfo(String packageName) {
    try {
        PackageInfo packageInfo = getPackageManager().getPackageInfo(
                            packageName, PackageManager.GET_SIGNATURES);
        Signature[] signs = packageInfo.signatures;
        Signature sign = signs[0];
        String signChars = new String(sign.toChars());
        System.out.println(signChars);
        Log.d("signChars", signChars);
        signChars = signChars + "\n" + parseSignature(sign.toByteArray());
        return signChars;

    } catch (Exception e) {
            e.printStackTrace();
            return "";
    }
}
{% endhighlight %}

得到了原版apk的签名，抓包时提交正确的signature值，可以跟服务器正常交互。
登录数据包为:
    identity=base64(用户名)&secret=base64(密码)=&integrityid=APK签名值

服务器返回信息为：
{% highlight javascript %}
{"response":{"status":"failure","msg":"Login failed"},"timeStamp":"1379429423","tZ":"America/New_York","reqResourceId":"webchal.isis.poly.edu","clientId":{"identitySig":"d033e22ae348aeb5660fc2140aec35850c4da997","role":"anonymous","accessToken":"YWRtaW46YW5vbnltb3VzOndlYmNoYWwuaXNpcy5wb2x5LmVkdQ=="}}
{% endhighlight %}

经过多次尝试，最终发现登录时增加一个role字段，值为base64(‘admin’)时，可以直接通过验证。
服务器返回信息为

    Key: Yo dawg I heard you leik to derp so i put a herp in your derp so you could herpderp while you derpderp


### References

1. <http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html>
