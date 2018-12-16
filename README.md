# X.509 数字证书

数据科学与计算机学院

16340296 张子权

Github:[https://github.com/zhangziquan/X.509-analysis](https://github.com/zhangziquan/X.509-analysis)

## X.509 证书概述

X.509 是一种公钥证书的格式标准，使用ASN.1语法来进行编码，被广泛应用于对电子邮件消息进行签名，对程序代码进行认证，以及对许多其他类型的数据进行认证等等。

X.509 证书是一些信息的集合，包含有关用户设备的信息，这个标准定义了证书中包含的信息，以及描述信息是如何编码的（即使用ASN.1来进行编码）。

---

## X.509 结构描述

* 基本结构
  * Version 版本号：标识证书的版本
  * Serial Number 序列号：由证书颁发者分配的本证书的唯一标识符。
  * Algorithm ID 签名算法：用于说明本证书所用的数字签名算法。
  * Issuer (CA’s name) 颁发者：证书颁发者的可识别名（DN）。
  * Validity 证书有效期：证书有效期的时间段。由”Not Before”和”Not After”两项组成，分别由UTC时间或一般的时间表示
  * Subject 证书主体：证书拥有者的可识别名
  * Subject Public Key Info 主体公钥信息：主体的公钥（以及算法标识符）
    * Public Key Algorithm 公钥算法
    * Subject Public Key 主体公钥
  * Issuer Unique Identifier 颁发者身份信息：证书颁发者的唯一标识符
  * Subject Unique Identifier 主体身份信息：证书拥有者的唯一标识符
* Extensions (Optional) 扩展部分 
  * 发行者密钥标识：证书所含密钥的唯一标识符
  * 基本约束：
  * 密钥使用：指明（限定）证书的公钥可以完成的功能或服务
  * CRL 分布点：CRL的分布地点

* Certificate Signature Algorithm 证书签名算法
* Certificate Signature 数字签名

---

## 数据结构

### 逻辑结构

集合结构

### 物理结构

顺序存储，TLV格式即 TAG——Length——Value
即TAG标识存储类型，Length标识长度，Value则为数据的值。
TAG一般为1个字节，表示数据类型。
Length字节不定：

1. 若长度值小于等于127，则用一个字节表示，bit8 = 0, bit7-bit1 存放长度值；
2. 若长度值大于127，则用多个字节表示，可以有2到127个字节。第一个字节的第8位为1，其它低7位给出后面Length域使用的字节的数量，从Length域第二个字节开始给出数据的长度，高位优先。

Value的字节数则由Length给出。

* 数据类型（TAG）包括：
    1. 简单类型：整型(INTERGER)、比特串(BIT STRING)、字节串(OCTET STRING)、对象标示符(OBJECT IDENTIFIER)、日期型(UTCTime)
    2. 复杂数据类型：顺序类型(SEQUENCE, SEQUENCE OF)

复杂的数据类型例如：

```java
   Certificate ::= SEQUENCE {
        tbsCertificate       SEQUENCE
        signatureAlgorithm   SEQUENCE
        signatureValue       BIT STRING
    }
```

---

## 算法

按字节读入文件
根据ASN.1的TLV结构进行解析，先获取TAG和Length，得到数据类型以及数据长度，之后根据不同的数据类型使用不同的输出。
简单的数据类型直接输出为字符串或十六进制数。
复杂的数据类型则使用递归进行处理，逐层解析。

---

## JAVA语言源代码

在Code文件夹中

## 编译运行结果

DEBUG：显示读取类型，长度以及获得的信息

![DEBUG](/Screenshot/DEBUG.png)

RELEASE：实验结果得到证书中的所有信息

![result1](/Screenshot/result1.png)
![result2](/Screenshot/result2.png)

实验对比：
![result1](/Screenshot/result3.png)

![result2](/Screenshot/result4.png)

![result2](/Screenshot/result5.png)

由上述结果可得所解析出的信息和系统解析的是一样的。

## 实验思考

垃圾蔡**，吔屎啦你

这次的实验的难点主要在于要先了解到X.509是用什么来进行编码的，特别是弄懂ASN.1的编码格式是TLV，之后根据这个来进行解码，因为证书并没有包含所有的数据类型，因此可以去掉一些无关代码，注重一些类似与String，Integer的基本类型的解码。

实验中有些字符串出现了乱码，例如CRL 分布点，但是看类型是BitString字符串，可能是由于系统编码的缘故，因为得到的后面的链接是对的。

总体来说还是掌握了X.509的格式标准，但感觉使用库还是最方便的。不用考虑很多bug。