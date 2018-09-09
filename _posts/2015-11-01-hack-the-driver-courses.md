---
layout: post
title: 手把手教你制作科目一刷学时神器
description: "captcha recognition"
tags: [python,captcha]
comments: true
image:
  background: bg-gray-paper.jpg
---

按照教练的指引登录上某驾驶技术教学网站，规定是要完成在线教学24个学时，才能参加科目一考试。

难道要老老实实的看满24个小时么？No。百度可以发现，网上有很多代刷学时的服务，甚至还有专门刷学时神器，都已经开始软件收费了。下面我们来看看，如何制作一个刷学时的“神器”。


## 刷学时

可以发现，目标网站悦驾网在每个重要的HTTP请求中都加入了一次性的Token，而且服务端对于每个视频长度做了校验，某些视频结束后还会有问答题。如果想通过脚本来逐个刷教学视频，会比较麻烦。再看看其他网站功能，发现做科目一模拟题的时间也会被算在在线学时中。模拟练习的交互过程如下：

1. 用户点击开始模拟练习。
2. 请求题目。
3. 用户提交答卷。提交所有答案，并结束模拟练习。

第三步请求数据包中包含了模拟练习的剩余时间，于是篡改剩余时间并提交，查看学习记录，发现练习的用时果然是通过总时间减去剩余时间进行统计的。这样就可以由用户自己控制每次练习所累积的在线学习时长，达到刷学时的目的。

第二步服务器返回的数据包是JSON格式的题目数据，而数据中已经包含了所有题目的正确答案。于是，“神器”思路如下：

1. 模拟用户开始练习。并解析获取表单中的一次性token
2. 获取题目，并解析出所有正确答案。
3. 模拟用户提交答卷，并设置请求包中表示剩余时间的参数为0。

这样一次就可以刷半个小时。代码如下：

{% highlight python %}
def attack(cookie):
    print "#STEP 1"
    r1 = requests.get("http://car.monicar.cn/StudentManage/KmyMnks",headers={'Cookie':cookie})
    m = re.search(r'__RequestVerificationToken" type="hidden" value="(.*?)" />', r1.content)
    if m:
        print "token: "+m.group(1)
        token = m.group(1)
    else:
        print "no match"
 
    print "#STEP 2"
    r2 = requests.get("http://car.monicar.cn/StudentManage/GetCurrExams",headers={'Cookie':cookie})
    exams = json.loads(r2.content)
    right_answer = '["' + '","'.join(exams['dicAnswer']) + '"]'
    print 'right_answer: '+right_answer
 
    time.sleep(3)
    print "#STEP 3"
    data = {'__RequestVerificationToken':token, 'leftTime':'14:44', 'examCarType':'C1', 'kmType':'1', 'DicUserAnswer':right_answer, 'verifyScore':'100'}
    r3 = requests.post("http://car.monicar.cn/StudentManage/NewGetResult", data=data, headers={'Cookie':cookie})
    print r3.content
{% endhighlight %}

这里需要传入用户自己登录态的Cookie。而对于普通用户来说，这个体验肯定是不符合“神器”标准的。于是我们需要模拟用户登录，这样就得对网站登陆框进行验证码识别。

![verify_image]({{ site.url }}/images/articles/201511/verify_image.jpg)

验证码为4位纯数字验证码，干扰并不是很强。

## 验证码识别

光学字符识别(OCR,Optical Character Recognition)是指对文本资料进行扫描，然后对图像文件进行分析处理，获取文字及版面信息的过程。

Tesseract的OCR引擎最先由HP实验室于1985年开始研发，至1995年时已经成为OCR业内最准确的三款识别引擎之一。然后HP不久却放弃了OCR业务，数年后Google对Tesseract进行改进、消除Bug、优化工作。

Python下也有很多封装Tesseract的类库。这里我们使用了[pytesseract](https://pypi.python.org/pypi/pytesseract)进行识别，使用[PIL](http://www.pythonware.com/products/pil/)工具对图像进行处理。
       
**安装*tesseract-ocr*:**

    brew install tesseract
    https://github.com/tesseract-ocr/tesseract

***Tips***

安装PIL时，可能会报错：

    _imagingft.c:73:10: fatal error: 'freetype/fterrors.h' file not found

**解决方法如下：**

安装[freetype](http://www.freetype.org/download.html)后执行 

    ln -s /usr/local/include/freetype2 /usr/local/include/freetype


pytesseract的原理是使用PIL对图片进行一定处理后，通过subprocess.Popen调用tesseract命令进行图像识别。而Tesseract只能识别黑白图片。所以我们需要对验证码进行一定的预处理，将图像二值化处理，转成黑白图片。

PIL可以对图像的颜色进行转换，支持24位彩色、8位灰度图和二值图等模式。

{% highlight python %}
Image.open('verify_image.jpg').convert('1')
{% endhighlight %}

convert(mode)函数，mode表示所输出的颜色模式，”L”表示灰度，”1”表示二值图模式。convert(‘1’)使用固定的阈值127实现二值化，即灰度高于127的像素值为白色，而灰度低于127的像素值为黑色。

而对于目标网站的验证码，可以看到，噪点均为浅色的灰白线条，我们可以调高二值化的阈值，减少验证码中的数字部分信息的丢失，一定程度上提高识别准确率。代码如下：

{% highlight python %}
def parse_verify_code():
    image = Image.open('verify_image.jpg')
    Limage = image.convert('L')
    Limage.save('verify_image_l.jpg')
    threshold = 180
    table = []
    for  i  in  range( 256 ):
        if  i  <  threshold:
            table.append(0)
        else :
            table.append(1)
 
    Bimage  =  Limage.point(table,'1')
    Bimage.save('verify_image_b.jpg')
 
    verify_code = pytesseract.image_to_string(Bimage,lang='eng',config='digits')
    print "verify code is " + verify_code
 
    return verify_code
 {% endhighlight %}

## 模拟登陆

最后我们结合识别出来的验证码，模拟用户登录。

请求目标网站，获取Session Cookie
获取验证码图片并识别
提交登录请求，解析并保存响应包中的登录态Cookie
代码如下：

{% highlight python %}
User_Cookie = ""
 
def parse_set_cookie(setcookies):
    result = ""
    for sc in setcookies:
        result += sc.split(";")[0]+";"
    return result
 
def get(url,cookie):
    r = requests.get(url,headers={'cookie':cookie})
    if 'set-cookie' in r.headers:
        setcookies = r.headers['set-cookie'].split(",")
        global User_Cookie
        User_Cookie += parse_set_cookie(setcookies)
    return r
 
def init():
    r01 = get("http://car.monicar.cn/",User_Cookie)
    #print User_Cookie
    r02 = get("http://car.monicar.cn/SecurityCode/CreateImageCode",User_Cookie)
    #print User_Cookie
    verify_image = open('verify_image.jpg','w')
    verify_image.write(r02.content)
    verify_image.close()
 
def parse_verify_code():
    image = Image.open('verify_image.jpg')
    Limage = image.convert('L')
    Limage.save('verify_image_l.jpg')
    threshold = 180
    table = []
    for  i  in  range( 256 ):
        if  i  <  threshold:
            table.append(0)
        else :
            table.append(1)
 
    Bimage  =  Limage.point(table,'1')
    Bimage.save('verify_image_b.jpg')
 
    verify_code = pytesseract.image_to_string(Bimage,lang='eng',config='digits')
    print "verify code is " + verify_code
 
    return verify_code
 
def login(username,password,code,cookie):
    print 'logining...'
    data = {'stucard':username, 'stupwd':password, 'yzm':code, 'check':'0'}
    r = requests.post("http://car.monicar.cn/Account/LogOnStu",data=data,headers={'Cookie':cookie})
    print r.content
    if '8' in r.content:
        #print r.headers['set-cookie']
        setcookies = r.headers['set-cookie'].split(",")
        global User_Cookie
        User_Cookie += parse_set_cookie(setcookies)
        return True
    else:
        return False
{% endhighlight %}


## 结束

验证码识别成功率基本50%左右，平均两次就可登陆成功。一次登录成功之后就可以利用Cookie刷学时了。可以设置每次间隔1800秒刷一次。

{% highlight python %}
import requests
import json
import re
import time
import pytesseract
import Image
import subprocess
import os
 
'''省略前文代码'''
 
if __name__ == "__main__":
 
    username = "xxxxxxxx"
    password = "xxxxxx"
 
    for i in xrange(10):
        init()
        code = parse_verify_code()
        if login(username, password, code, User_Cookie):
            print 'Login Success'
            #print User_Cookie
            break
        else:
            print 'Login Failed. Retrying...'
 
    for i in xrange(8):
        time.sleep(1800)
        attack(User_Cookie)
{% endhighlight %}

*PS: 该学的驾驶理论知识还是要好好学喔。*
