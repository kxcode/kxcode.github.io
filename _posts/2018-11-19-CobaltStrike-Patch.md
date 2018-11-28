---
layout: post
title: 内网渗透有它就够了，手把手教你破解CobaltStrike3.12
description: "Patch CobaltStrike Step by Step"
tags: [CobaltStrike, APT, Pentest]
image:
  background: bg-white-wall2.jpg
---

# 1 - 概述

CobaltStrike是一款内网渗透的商业远控软件，支持自定义脚本扩展，功能非常强大。前段时间Github上有好心人放出了CobaltStrike3.12的试用版，接着Lz1y很快就放出了破解版，加上热心老哥提供了的[xor64.bin](https://github.com/verctor/CS_xor64)（试用版中没有这个文件），一个比较完美的最新可用版本诞生了。下面我们看下最新试用版是如何被完美破解的。

# 2 - 上手

CobaltStrike（下面简称CS）主体代码是用Java开发的，逆起来比较友好。用jd-gui反编译cobaltstrike.jar文件，可以看到代码几乎没有做防破解。Java源码没有任何混淆。但是查看反编译的源码时，很多地方出现了`// INTERNAL ERROR //`，这里我推荐一款Java反编译工具`luyten`，几乎可以100%反编译获得cobaltstrike.jar源码。

CS的License处理逻辑在`common/License.java`文件中：

```java
package common;

import aggressor.*;
import javax.swing.*;
import java.awt.*;

public class License
{
    private static long life;
    private static long today;
    private static long start;
    private static long difference;
    
    private static long getTimeSinceStart() {
        final Prefs options = Prefs.getPreferences();
        License.today = System.currentTimeMillis();
        License.start = options.getLongNumber("cobaltstrike.start.int", 0L);
        if (License.start == 0L) {
            options.set("cobaltstrike.start.int", License.today + "");
            options.save();
            License.start = License.today;
        }
        return License.difference = (License.today - License.start) / 86400000L;
    }
    
    public static void checkLicenseGUI(final Authorization auth) {
        getTimeSinceStart();
        if (License.difference > License.life || License.today - License.start < 0L) {
            JOptionPane.showMessageDialog(null, "Your Cobalt Strike trial is now expired.\nPlease purchase a license and use the\nsoftware update feature to continue.\n\nFor details, visit:\nhttps://www.cobaltstrike.com/", null, 0);
            System.exit(0);
        }
        else {
            final long left = License.life - License.difference;
            String form = left + " day";
            if (left != 1L) {
                form += "s";
            }
            CommonUtils.print_warn("This is a trial version of Cobalt Strike. You have " + form + " left of your trial. If you purchased Cobalt Strike. Run the Update program and enter your license.");
            CommonUtils.print_trial("WARNING! This trial is *built* to get caught by standard defenses. The licensed product does not have these restrictions. See: http://blog.cobaltstrike.com/2015/10/14/the-cobalt-strike-trials-evil-bit/");
            JOptionPane.showMessageDialog(null, "This is a trial version of Cobalt Strike.\nYou have " + form + " left of your trial.\n\nIf you purchased Cobalt Strike. Run the\nUpdate program and enter your license.", null, 1);
        }
    }
    
    public static boolean isTrial() {
        return true;
    }
    
    public static void checkLicenseConsole(final Authorization auth) {
        getTimeSinceStart();
        if (License.difference > License.life || License.today - License.start < 0L) {
            CommonUtils.print_error("Your Cobalt Strike trial is now expired. Please purchase a license and use the software update feature to continue. For details, visit: https://www.cobaltstrike.com/");
            System.exit(0);
        }
        else {
            final long left = License.life - License.difference;
            String form = left + " day";
            if (left != 1L) {
                form += "s";
            }
            CommonUtils.print_warn("This is a trial version of Cobalt Strike. You have " + form + " left of your trial. If you purchased Cobalt Strike. Run the Update program and enter your license.");
            CommonUtils.print_trial("WARNING! This trial is *built* to get caught by standard defenses. The licensed product does not have these restrictions. See: http://blog.cobaltstrike.com/2015/10/14/the-cobalt-strike-trials-evil-bit/");
        }
    }
    
    static {
        License.life = 21L;
        License.today = 0L;
        License.start = 0L;
        License.difference = 0L;
    }
}

```

代码逻辑很清晰，这里我们有两个方向进行patch：

1. 修改`License.life`无限延长试用
2. 修改`isTrial()`返回值，伪造成正式版

因为CS很多地方的试用版和正式版处理逻辑不同，所以修改了`isTrial()`返回值之后，我们还需要修改所有调用了`isTrial()`函数的地方，对代码进行调整。另外试用版CS留了一些特征指纹和限制，我们也需要去除相应的特征代码。

## 修改重打包

既然知道了破解思路，我们看下如何动手操作去修改源码并重编译。Java编程中我们可以使用`jar`工具将一系列的.class文件打包成jar包，供其他java程序使用。我们也可以修改jar包中.class文件的内容，并重新编译打包。比如修改demo.jar中的kingx.class并重新编译的过程如下：

1. 使用jd-gui、luyten等工具把demo.jar包中的class反编译成源码，从中提取得到kingx.java

2. 执行`jar xvf demo.jar` 解压demo.jar得到jar包的子文件（注意会解压到当前目录），将kingx.java文件放置到与kingx.class文件同一目录

3. 执行`javac -cp a.jar;b.jar;c.jar kingx.java`重新编译。(或者javac -cp demo.jar kingx.java)得到新的kingx.class文件。

    其中a.jar、b.jar、c.jar是依赖包，一般直接依赖一个原始解压的demo.jar包即可

4. 确保编译后的kingx.class替换了原来的kingx.class文件（可以通过jd-gui反编译查看）

5. 执行`jar -uvf  demo.jar com/some/path/kingx.class`更新demo.jar包


更新jar包中的class文件时，新的class文件目录路径需要与原package路径保持一致。比如修改了`aggressor.AggressorClient.java`并重新编译之后，更新jar包的命令如下：

```
17:16 KINGX modified_java_files >jar -uvf cobaltstrike-with-xor64.jar aggressor/AggressorClient*.class
正在添加: aggressor/AggressorClient$1.class(输入 = 650) (输出 = 403)(压缩了 38%)
正在添加: aggressor/AggressorClient$2.class(输入 = 1263) (输出 = 704)(压缩了 44%)
正在添加: aggressor/AggressorClient.class(输入 = 11115) (输出 = 5196)(压缩了 53%)

```

## 可能遇到的问题

修改后的java文件在重新编译为class文件时，可能会遇到很多奇怪的报错。有时候是因为反编译出的源码存在错误导致的，这个时候我们可以将luyten、jad、jd-gui等反编译工具结合使用，尽量还原成正确的源码，再重新编译。
比如：AggressorClient.java，`jad aggressor/AggressorClient*.class`和`luyten`反编译得到的源码是不一样的。


# 3 - 试用版Patch详细分析

*Tips: 以下代码片段中行首的 - 代表删除，+ 代表新增*

## Patch 试用版本
修改common.License，去掉checkLicenseGUI()、checkLicenseConsole()函数体，修改isTrial()返回值为false

## 修改主程序标题
aggressor.AggressorClient，修改getTitle()函数

## 解除listener同类数量限制  

一个teamserver默认只能监听一个listener，可以通过修改代码去除限制。



aggressor.dialogs.ListenerDialog，去除以下代码：
```java
...
else if (Listener.isEgressBeacon(payload) && DataUtils.isBeaconDefined(this.datal) && !name.equals(DataUtils.getEgressBeaconListener(this.datal))) {
    DialogUtils.showError("You may only define one egress Beacon per team server.\nThere are a few things I need to sort before you can\nput multiple Beacon HTTP/DNS listeners on one server.\nSpin up a new team server and add your listener there.");
}
...
```

## 去除EICAR后门指纹特征  

试用版有几个地方存在EICAR特征字符：`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`，都需要进行清理：

### common.ListenerConfig
修改pad()函数：

```java
-  result.append("5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\u0000");
+  result.append("123\u0000");
```

### resources/template.x64.ps1、resources/template.x86.ps1

```java
-  $eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
+  $eicar = ''
```

### server.ProfileEdits

```java
-  c2profile.addCommand(".http-get.server", "!header", "X-Malware: X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
-  c2profile.addCommand(".http-post.server", "!header", "X-Malware: X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
-  c2profile.addCommand(".http-stager.server", "!header", "X-Malware: X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
-  c2profile.addCommand(".stage.transform-x86", "append", "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
-  c2profile.addCommand(".stage.transform-x64", "append", "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
```

### common.ArtifactUtils
因为已经修改了License.isTrial()返回值为false，所以下面这段改不改也没什么影响。

```java
if (License.isTrial()) {
    packer.addString("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
    CommonUtils.print_trial("Added EICAR string to " + s);
}
```

## 添加XOR64.BIN

生成payload时，会调用common.ArtifactUtils中的XorEncode()进行编码：

```java
public static byte[] _XorEncode(final byte[] data, final String arch) {
    AssertUtils.TestArch(arch);
    if ("x86".equals(arch)) {
        final byte[] decoder = XorStub();
        final byte[] payload = XorEncoder.encode(data);
        return CommonUtils.join(decoder, payload);
    }
    if ("x64".equals(arch)) {
        final byte[] decoder = CommonUtils.readResource("resources/xor64.bin");
        final byte[] payload = XorEncoder.encode(data);
        return CommonUtils.join(decoder, payload);
    }
    return new byte[0];
}

public static byte[] XorEncode(final byte[] data, final String arch) {
    if (License.isTrial()) {
        CommonUtils.print_trial("Disabled " + arch + " payload stage encoding.");
        return data;
    }
    AssertUtils.Test(data.length > 16384, "XorEncode used on a stager (or some other small thing)");
    return _XorEncode(data, arch);
}
```

试用版不会进行`payload stage encoding`，所以试用版软件包中并没有带xor.bin/xor64.bin文件，如果有这两个文件的话，可以添加到`resources/xor.bin`、`resources/xor64.bin`路径下。Github上有热心老哥提供了xor64的生成脚本：<https://github.com/verctor/CS_xor64>

源码逐个修改完，重新编译更新到cobaltstrike.jar包中，再拷贝替换掉原版的jar包就OK了。