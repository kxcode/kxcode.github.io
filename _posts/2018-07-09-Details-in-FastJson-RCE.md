---
layout: post
title: FastJson反序列化漏洞利用的三个细节 - TemplatesImpl的利用链
description: "Vulnerability - Java FastJson"
tags: [Vulnerability, Java]
image:
  background: triangular.png
---
# 0. 前言

记录在FastJson反序列化RCE漏洞分析和利用时的一些细节问题。

# 1. TemplatesImpl的利用链

## 关于 parse 和 parseObject

FastJson中的 parse() 和 parseObject()方法都可以用来将JSON字符串反序列化成Java对象，parseObject() 本质上也是调用 parse() 进行反序列化的。但是 parseObject() 会额外的将Java对象转为 JSONObject对象，即 JSON.toJSON()。所以进行反序列化时的细节区别在于，parse() 会识别并调用目标类的 setter 方法及某些特定条件的 getter 方法，而 parseObject() 由于多执行了 JSON.toJSON(obj)，所以在处理过程中会调用反序列化目标类的所有 setter 和 getter 方法。parseObject() 的源代码如下：

```java
public static JSONObject parseObject(String text) {
        Object obj = parse(text);
        if (obj instanceof JSONObject) {
            return (JSONObject) obj;
        }

        return (JSONObject) JSON.toJSON(obj);
}
```

举个简单的例子：

```java
public class FastJsonTest {

    public String name;
    public String age;
    public FastJsonTest() throws IOException{
    }

    public void setName(String test) {
        System.out.println("name setter called");
        this.name = test;
    }

    public String getName() {
        System.out.println("name getter called");
        return this.name;
    }

    public String getAge(){
        System.out.println("age getter called");
        return this.age;
    }

    public static void main(String[] args) {
        Object obj = JSON.parse("{\"@type\":\"fastjsontest.FastJsonTest\",\"name\":\"thisisname\", \"age\":\"thisisage\"}");
        System.out.println(obj);

        Object obj2 = JSON.parseObject("{\"@type\":\"fastjsontest.FastJsonTest\",\"name\":\"thisisname\", \"age\":\"thisisage\"}");
        System.out.println(obj2);
    }

}
```

上述代码运行后可以看到，执行parse() 时，只有 setName() 会被调用。执行parseObject() 时，setName()、getAge()、getName() 均会被调用。


## 为什么会触发getOutputProperties()

感觉上 parse() 进行反序列化创建Java类应该只会调用 setter 方法进行成员变量赋值才对，会什么会触发TemplatesImpl类中的 getOutputProperties() 方法呢？

另外 _outputProperties 成员变量和 getOutputProperties() 明明差了一个`_`字符，是怎么被 FastJson 关联上的?

如上一小节所述，parse() 进行反序列化时其实会调用某些特定的 getter 方法进行字段解析，而 TemplatesImpl类中的 getOutputProperties() 方法恰好满足这一条件。

FastJson反序列化到Java类时主要逻辑如下：

1. 获取并保存目标Java类中的成员变量、setter、getter。
2. 解析JSON字符串，对字段逐个处理，调用相应的setter、getter进行变量赋值。

        
我们先看第一步，这里由 JavaBeanInfo.build() 进行处理，FastJson会创建一个filedList数组，用来保存目标Java类的成员变量以及相应的setter或getter方法信息，供后续反序列化字段时调用。

filedList大致结构如下：

    [
        {
            name:"outputProperties",
            method:{
                clazz:{},
                name:"getOutputProperties",
                returnType:{},
                ...
            }
        }
    ]

FastJson并不是直接反射获取目标Java类的成员变量的，而是会对setter、getter、成员变量分别进行处理，智能提取出成员变量信息。逻辑如下：

1. 识别setter方法名，并根据setter方法名提取出成员变量名。如：识别出setAge()方法，FastJson会提取出age变量名并插入filedList数组。
2. 通过clazz.getFields()获取成员变量。
3. 识别getter方法名，并根据getter方法名提取出成员变量名。

可以看到在 JavaBeanInfo.build() 中，有一段代码会对getter方法进行判断，在某些特殊条件下，会从getter方法中提取出成员变量名并附加到filedList数组中。而TemplatesImpl类中的 getOutputProperties() 正好满足这个特定条件。getter方法的处理代码为：

```java
JavaBeanInfo.java

public static JavaBeanInfo build(Class<?> clazz, Type type, PropertyNamingStrategy propertyNamingStrategy) {
    ...
    for (Method method : clazz.getMethods()) { // getter methods
        String methodName = method.getName();
        if (methodName.length() < 4) {
            continue;
        }

        if (Modifier.isStatic(method.getModifiers())) {
            continue;
        }

        if (methodName.startsWith("get") && Character.isUpperCase(methodName.charAt(3))) {
            if (method.getParameterTypes().length != 0) {
                continue;
            }

            // 关键条件

            if (Collection.class.isAssignableFrom(method.getReturnType()) //
                || Map.class.isAssignableFrom(method.getReturnType()) //
                || AtomicBoolean.class == method.getReturnType() //
                || AtomicInteger.class == method.getReturnType() //
                || AtomicLong.class == method.getReturnType() //
            ) {
                String propertyName;

                JSONField annotation = method.getAnnotation(JSONField.class);
                if (annotation != null && annotation.deserialize()) {
                    continue;
                }
                
                if (annotation != null && annotation.name().length() > 0) {
                    propertyName = annotation.name();
                } else {
                    propertyName = Character.toLowerCase(methodName.charAt(3)) + methodName.substring(4);
                }
                
                FieldInfo fieldInfo = getField(fieldList, propertyName);
                if (fieldInfo != null) {
                    continue;
                }

                if (propertyNamingStrategy != null) {
                    propertyName = propertyNamingStrategy.translate(propertyName);
                }
                
                add(fieldList, new FieldInfo(propertyName, method, null, clazz, type, 0, 0, 0, annotation, null, null));
            }
        }
    }
    ...
}
```

接下来，FastJson会语义分析JSON字符串。根据字段key，调用filedList数组中存储的相应方法进行变量初始化赋值。具体逻辑在 parseField() 中实现：

```java
JavaBeanDeserializer

public boolean parseField(DefaultJSONParser parser, String key, Object object, Type objectType,
                              Map<String, Object> fieldValues) {
        JSONLexer lexer = parser.lexer; // xxx

        FieldDeserializer fieldDeserializer = smartMatch(key);

        ...

        return true;
    }
```

这里调用了一个神奇的 smartMatch() 方法，smartMatch()时会替换掉字段key中的`_`，从而 _outputProperties 和 getOutputProperties() 可以成功关联上。


```java
JavaBeanDeserializer

public FieldDeserializer smartMatch(String key) {
        if (fieldDeserializer == null) {
            boolean snakeOrkebab = false;
            String key2 = null;
            for (int i = 0; i < key.length(); ++i) {
                char ch = key.charAt(i);
                if (ch == '_') {
                    snakeOrkebab = true;
                    key2 = key.replaceAll("_", "");
                    break;
                } else if (ch == '-') {
                    snakeOrkebab = true;
                    key2 = key.replaceAll("-", "");
                    break;
                }
            }
            if (snakeOrkebab) {
                fieldDeserializer = getFieldDeserializer(key2);
                if (fieldDeserializer == null) {
                    for (FieldDeserializer fieldDeser : sortedFieldDeserializers) {
                        if (fieldDeser.fieldInfo.name.equalsIgnoreCase(key2)) {
                            fieldDeserializer = fieldDeser;
                            break;
                        }
                    }
                }
            }
        }
```

## 为什么需要对_bytecodes进行Base64编码
    
细心的你可以发现，PoC中的 _bytecodes 字段是经过Base64编码的。为什么要这么做呢？
分析FastJson对JSON字符串的解析过程，原来FastJson提取byte[]数组字段值时会进行Base64解码，所以我们构造payload时需要对 _bytecodes 进行Base64处理。FastJson的处理代码如下：


```java
ObjectArrayCodec
    public <T> T deserialze(DefaultJSONParser parser, Type type, Object fieldName) {
        final JSONLexer lexer = parser.lexer;
        // ......省略部分代码
        if (lexer.token() == JSONToken.LITERAL_STRING) {
            byte[] bytes = lexer.bytesValue();  // ... 在这里解析byte数组值
            lexer.nextToken(JSONToken.COMMA);
            return (T) bytes;
        }

// 接着调用JSONScanner.bytesValue()

JSONScanner
    public byte[] bytesValue() {
      return IOUtils.decodeBase64(text, np + 1, sp);
    }
``` 