---
layout: post
title: Keras MNIST MLP示例详解
description: "Keras MNIST MLP"
tags: [bigdata,spark]
image:
  background: triangular.png
---

## 0x01 代码分解

```python
#coding=utf-8 
'''Trains a simple deep NN on the MNIST dataset.

Gets to 98.40% test accuracy after 20 epochs
(there is *a lot* of margin for parameter tuning).
2 seconds per epoch on a K520 GPU.
'''

from __future__ import print_function

import keras
from keras.datasets import mnist
from keras.models import Sequential
from keras.layers import Dense, Dropout
from keras.optimizers import RMSprop


batch_size = 128
num_classes = 10
epochs = 20

# 本数据库有60,000个用于训练的28*28的灰度手写数字图片，10,000个测试图片
# the data, shuffled and split between train and test sets
(x_train, y_train), (x_test, y_test) = mnist.load_data()
# X_train 大小为60000*28*28，y_train 为60000*1，
# X_test 为10000*28*28，y_train 为10000*1
# 每一幅图是28*28大小
x_train = x_train.reshape(60000, 784)	
# 把X_train变形为 60000*784 （即将每幅图片变为一个向量）
x_test = x_test.reshape(10000, 784)
# 把X_test变形为 10000*784 （即将每幅图片变为一个向量）
x_train = x_train.astype('float32')
x_test = x_test.astype('float32')
x_train /= 255	# 数据大小由0~255归一化到0~1
x_test /= 255
print(x_train.shape[0], 'train samples')
print(x_test.shape[0], 'test samples')

# 将分类向量转化为二元分类矩阵(one hot)
# 注意: 当使用"categorical_crossentropy"作为目标函数（损失函数）时,
# 	标签应该为多类模式,即one-hot编码的向量,而不是单个数值。
# 	可以使用工具中的to_categorical函数完成该转换
y_train = keras.utils.to_categorical(y_train, num_classes)
y_test = keras.utils.to_categorical(y_test, num_classes)

# 模型定义
model = Sequential()
model.add(Dense(512, activation='relu', input_shape=(784,)))	
# 添加第一个层，并设置输入数据shape，为784维的一阶向量
# 	全连接层，784维输入，512维输出， relu 激活函数
model.add(Dropout(0.2))											
model.add(Dense(512, activation='relu'))
model.add(Dropout(0.2))
model.add(Dense(10, activation='softmax'))
model.summary()

# 模型编译
model.compile(loss='categorical_crossentropy',
              optimizer=RMSprop(),
              metrics=['accuracy'])
# 损失函数，categorical_crossentropy：亦称作多类的对数损失，
# 	注意使用该目标函数时，需要将标签转化为形如(nb_samples, nb_classes)的二值序列
# 优化器optimizer，该参数可指定为已预定义的优化器名，如rmsprop、adagrad，或一个Optimizer类的对象。
# 	RMSprop，除学习率可调整外（lr：大于0的浮点数，学习率），建议保持优化器的其他默认参数不变。
# 	该优化器通常是面对递归神经网络时的一个良好选择
# 指标列表metrics：对分类问题，我们一般将该列表设置为metrics=['accuracy']。
# 	指标可以是一个预定义指标的名字,也可以是一个用户定制的函数。
# 	指标函数应该返回单个张量,或一个完成metric_name - > metric_value映射的字典。


history = model.fit(x_train, y_train,
                    batch_size=batch_size,
                    epochs=epochs,
                    verbose=1,
                    validation_data=(x_test, y_test))
score = model.evaluate(x_test, y_test, verbose=0)
print('Test loss:', score[0])
print('Test accuracy:', score[1])


```
