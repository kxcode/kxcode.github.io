---
layout: post
title: 数据挖掘 - Python数据可视化
description: "Data finds abnormal"
tags: [DataScience,MachineLearning,APT]
image:
  background: triangular.png
---

## 1. 概述



## 2. 直方图

最简单的用法：
```python
import matplotlib.pyplot as plt

plt.hist([1,2,2,2,3,3,4,5])
plt.show()
```

复杂点的用法：

hist(x,bins) 函数中bins是指直方图的总个数，个数越多，条形带越紧密
```python
# coding=utf-8
import numpy as np
from numpy.linalg import cholesky
import matplotlib.pyplot as plt

sampleNo = 1000;
# 一维正态分布
# 下面三种方式是等效的
mu = 3
sigma = 0.1
np.random.seed(0)
s = np.random.normal(mu, sigma, sampleNo )
#s = np.random.rand(1, sampleNo )
plt.subplot(141)
plt.hist(s, 10, normed=True)   #####bins=10

np.random.seed(0)
s = sigma * np.random.randn(sampleNo ) + mu
plt.subplot(142)
plt.hist(s, 30, normed=True)   #####bins=30

np.random.seed(0)
s = sigma * np.random.standard_normal(sampleNo ) + mu
plt.subplot(143)
plt.hist(s, 30, normed=True)   #####bins=30

# 二维正态分布
mu = np.array([[1, 5]])
Sigma = np.array([[1, 0.5], [1.5, 3]])
R = cholesky(Sigma)
s = np.dot(np.random.randn(sampleNo, 2), R) + mu
plt.subplot(144)
# 注意绘制的是散点图，而不是直方图
plt.plot(s[:,0],s[:,1],'+')
plt.show()
```

