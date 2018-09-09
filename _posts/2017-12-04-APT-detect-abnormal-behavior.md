---
layout: post
title: 数据挖掘 - 相似性度量
description: "Data finds abnormal"
tags: [DataScience,MachineLearning,APT]
image:
  background: triangular.png
---

## 1. 概述

Detecting anomalies in time series on daily or weekly data at scale. Anomalies indicate exceptional events.

Now shift context with me to security-specific events and incidents, as the pertain to security monitoring, incident response, and threat hunting

在基于大数据的安全防御建设中，为了从数据挖掘出异常行为，通常我们需要计算不同个体之间的差异，从而通过相似性和类别来判定异常行为和正常行为，找出偏离用户行为基线的异常点。数据科学中有很多常用的”距离“、”相似性“的计算方法。我们可以根据数据特性而采用不同的度量方法。比如：

- 空间：欧氏距离
- 路径：曼哈顿距离
- 国际象棋国王：切比雪夫距离

以上三种的统一形式: 闵可夫斯基距离

- 加权：标准化欧氏距离
- 排除量纲和依存：马氏距离
- 向量差距：夹角余弦
- 编码差别：汉明距离
- 集合近似度：杰卡德类似系数与距离
- 相关：相关系数与相关距离

定义一个距离函数，需要满足几个准则：

1. 仅到自己的距离为零
2. 距离非负
3. 三角形法则，两边之和大于第三边


## 2. 余弦相似度（向量内积）

适合高维度向量vectors的相似度计算。两个向量的Cosine距离就是这两个向量之间的夹角。
Cosine值越接近0表示夹角越大，越接近于1表示夹角越小。

http://www.cnblogs.com/chaosimple/p/3160839.html

余弦相似度，又称为余弦相似性，是通过计算两个向量的夹角余弦值来评估他们的相似度。余弦相似度将向量根据坐标值，绘制到向量空间中，如最常见的二维空间。

将向量根据坐标值，绘制到向量空间中。如最常见的二维空间。
　　
求得他们的夹角，并得出夹角对应的余弦值，此余弦值就可以用来表征，这两个向量的相似性。夹角越小，余弦值越接近于1，它们的方向更加吻合，则越相似。

### 计算方法
假设两个向量，a向量是(x1,x2,x3...)   b向量是 (y1,y2,y3...)

假设a向量是（x1, y1,...），b向量是(x2, y2,...)

x1*x2+y1*y2+....../更号(x1^2+y1^2...)+更号(x2^2+y2^2...)


```python
from scipy.spatial.distance import cosine
cosine_value = 1-cosine(p,q)	
```

```python
#-*-coding:utf-8-*-
def cos(vector1,vector2):
    dot_product = 0.0;
    normA = 0.0;
    normB = 0.0;
    for a,b in zip(vector1,vector2):
        dot_product += a*b
        normA += a**2
        normB += b**2
    if normA == 0.0 or normB==0.0:
        return None
    else:
        return dot_product / ((normA*normB)**0.5)
```


## 3. 欧氏距离
只的是在多维空间中两个点之间的真实距离，或者向量的自然长度（即该点到原点的距离）。在数学上也可以成为范数。

### 计算方法
两个向量各个元素的差值的平方求和然后求平方根。
	
	dist = numpy.sqrt(numpy.sum(numpy.square(vec1 - vec2)))  
	或者
	dist = numpy.linalg.norm(vec1 - vec2)



## 4. KL散度（相对熵） Kullback-Leibler divergence 
KL散度是用来度量使用基于Q的编码来编码来自P的样本平均所需的额外的位元数，是描述两个概率分布P和Q差异的一种方法。测量两个概率分布之间的距离。可以看做是概率分布P到目标概率Q之间距离。一般情况下，P表示数据的真是分布，Q表示数据的理论分布，也可以理解为影响P分布的一种因素。计算公式为：

　　　　　　　　　　　　　　　　　　　　　　DKL(P||Q) =ΣP(i)log(P(i)/Q(i)) 

KL散度是不对称的，如果希望对称：

Ds(p1, p2) = (D(p1, p2) + D(p2, p1)) / 2

**Tips:**

KL散度需要满足

- 概率P和Q各自总和均为1
- 概率P(i)和Q(i)均大于0

时才有定义。


### 计算方法

```python
	import scipy.stats
	a = [0.0,0.0,0.0,0.0,970.0,0.0,0.0,0.0,0.0,0.0]
	b = [0.0,0.0,0.0,0.0,102.0,75.625,0.0,0.0,0.0,0.0]
	KL = scipy.stats.entropy(a, b) 
```

scipy.stats.entropy(p, q) 会计算：

	S = sum(pk * log(pk / qk), axis=0).

除了用函数库之外，也可以自行编程实现计算：

```python
	import numpy as np

	a = [0.00000001,0.00000001,0.00000001,1.001,1.0,0.1,0.00000001,0.00000001,0.00000001,0.00000001]
	b = [0.00000001,0.00000001,0.00000001,0.00000000001,0.9,0.1,0.00000001,0.00000001,0.00000001,0.00000001]
	# 归一化
	pa = a/np.sum(a)
	pb = b/np.sum(b)
	KL = 0.0
	for i in range(10):
	    KL += pa[i] * np.log(pa[i] / pb[i])
	    # print(str(px[i]) + ' ' + str(py[i]) + ' ' + str(px[i] * np.log(px[i] / py[i])))
	print(KL)
```

### 适用场景

《【原】浅谈KL散度（相对熵）在用户画像中的应用》https://www.cnblogs.com/charlotte77/p/5392052.html


## 5. K-S统计作为距离度量

## 6. 检测分布尖峰的变化


## References 使用 Anomalize 算法进行异常检测与威胁狩猎
https://holisticinfosec.blogspot.com/2018/06/toolsmith-133-anomaly-detection-threat.html