---
layout: post
title: 下一代Web基石 - WebAssembly
description: "WebAssembly"
tags: [前端]
image:
  background: triangular.png
---
# 0. 前言
WebAssembly/wasm 是一个由JavsScript进化来的，用于在浏览器内编写客户端脚本的底层的字节码格式。最初目的是支持编译C和C++语言。


# 1. 使用 WebAssembly

## 以C语言为例
比如C语言代码如下:

math.c

```c
int square (int x) {
  return x * x;
}
```

首先使用emscripten将c代码编译为wasm，生成math.wasm文件

	emcc math.c -Os -s WASM=1 -s SIDE_MODULE=1 -o math.wasm

然后在Web页面中加载math.wasm中的WebAssembly代码

```javascript
function loadWebAssembly(filename, imports = {}) {
  return fetch(filename)
    .then(response => response.arrayBuffer())
    .then(buffer => WebAssembly.compile(buffer))
    .then(module => {
      imports.env = imports.env || {}
      Object.assign(imports.env, {
        memoryBase: 0,
        tableBase: 0,
        memory: new WebAssembly.Memory({ initial: 256, maximum: 256 }),
        table: new WebAssembly.Table({ initial: 0, maximum: 0, element: 'anyfunc' })
      })
      return new WebAssembly.Instance(module, imports)
    })
}

loadWebAssembly('math.wasm')
      .then(instance => {
        const square = instance.exports._square
        console.log('2^2 =', square(2))
        console.log('3^2 =', square(3))
        console.log('(2 + 5)^2 =', square(2 + 5))
})

```

## 更多WebAssembly Demo

<https://github.com/Hanks10100/wasm-examples>

# 3. 相关工具

## 安装 emscripten
<http://kripken.github.io/emscripten-site/docs/getting_started/downloads.html>


  # Fetch the latest registry of available tools.
  ./emsdk update

  # Download and install the latest SDK tools.
  ./emsdk install latest

  # Make the "latest" SDK "active" for the current user. (writes ~/.emscripten file)
  ./emsdk activate latest

  # Activate PATH and other environment variables in the current terminal
  source ./emsdk_env.sh


wasm2wast math.wasm -o math.wast

## AdvancedTools
<http://webassembly.org/getting-started/advanced-tools/>

## The WebAssembly Binary Toolkit
<https://github.com/WebAssembly/wabt>

## OnlineDemo
<https://cdn.rawgit.com/WebAssembly/wabt/013802ca01035365e2459c70f0508481393ac075/demo/wasm2wast/>

## WebAssembly语法
<http://webassembly.org/docs/semantics/#type-parametric-operators>
