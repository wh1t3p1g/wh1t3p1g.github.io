---
title: 浅谈Java RMI Registry安全问题
tags: 
  - java
categories: notes
date: 2020-02-06 15:23:36
typora-root-url: ../../../source
---

## 0x00 前言

本文讲述了Java RMI Registry相关的反序列化问题，主讲Registry，后续补充了Client端和Server端的利用

<!-- more -->

## 0x01 原理

Java RMI流程可参考[1](https://xz.aliyun.com/t/2223)，出问题的位置在于：

### 情景一：Registry 接收bind/rebind请求

 从Client接收到的bind或rebind的`remote obj`，将由`sun/rmi/registry/RegistryImpl_Skel.java#dispatch`处理

（下图为JDK8u141之前的版本的实现）

![image-20200317175519024](/images/rmi-registry-security-problem-20200206/image-20200317175519024.png)

可以看到获取到的序列化数据直接调用了readObject函数，导致了常规的Java反序列化漏洞的触发。

这里我们只需要写一个bind或rebind的操作，即可攻击到RMI Registry。

#### 注意：bind/rebind请求的限制

Registry对于bind/rebind的请求，会去检查这个请求是否为本地请求，对于外部的请求，Registry会拒绝该请求。

这里思路是正确的，可以防止外部的恶意绑定，但是他在实现上存在问题。

JDK 8u141之前，首先会去接收传送过来的对象，并将其进行`readObject`反序列化，实际判断是否为本地请求，是在put新的绑定对象之前进行的。这意味着在checkAccess之前我们就可以完成反序列化操作，该限制并没有起到相应的作用。

![image-20200317175608779](/images/rmi-registry-security-problem-20200206/image-20200317175608779.png)

而在JDK 8u141版本之后，`sun/rmi/registry/RegistryImpl_Skel.java#dispatch`

![image-20200317181813002](/images/rmi-registry-security-problem-20200206/image-20200317181813002.png)

这里会先去判断是否为本地绑定请求，然后再进行反序列化。

所以如果要使用bind/rebind请求来远程攻击Registry，JDK版本必须在8u141之前

### 情景二：Registry接收lookup请求

由于bind/rebind请求在141后续版本存在限制，所以为了攻击Registry我们必须找其他的方法。

在RMI里客户端向Registry发起lookup请求是不限制请求源的，那么lookup是否可以被我们利用呢？

答案是肯定的，来看`sun.rmi.registry.RegistryImpl_Skel#dispatch`对于lookup请求的处理

![image-20200512141031125](/images/rmi-registry-security-problem-20200206/image-20200512141031125.png)

可以看到在这里，接收到lookup发送过来的内容时，也是直接对其进行反序列化操作。但是这里并没有bind/rebind的请求源限制，所以我们可以直接lookup发起对141版本之后的registry的攻击。

我们在构造lookup函数请求时，只需重新实现一下lookup函数的实现就可以了（这里将Naming.lookup和RegistryImpl_Stub.lookup进行了合并，并将传送过去的内容改成了任意的Object对象）。

![image-20200512141411217](/images/rmi-registry-security-problem-20200206/image-20200512141411217.png)

## 0x02 攻击Registry jdk<8u121

环境使用jdk8u111，该版本下的RMI Registry接收的remote obj只要继承了Remote类即可（原理见[2](https://www.freebuf.com/vuls/126499.html)），没有其他的限制。

ysoserial工具中的`ysoserial.exploit.RMIRegisterExploit`采用了代理Remote类的方式来解决这个限制。

使用如下命令即可

`java -cp ysoserial-0.0.6-SNAPSHOT-all.jar ysoserial.exploit.RMIRegistryExploit RMIRegisterHost RMIRegisterPort CommonsCollections7 "open /System/Applications/Calculator.app"`

### 简单看一下ysoserial.exploit.RMIRegisterExploit的原理

根据前面文章中的原理，我们传过去的对象必须要是一个继承了java.rmi.Remote接口的对象。这里ysoserial工具则直接利用动态代理的原理，对Remote类做代理，其处理的handler用了CommonsCollections中常用的AnnotationInvocationHandler。但其触发点变为handler的memberValues属性被反序列化所执行的利用链。

![image-20200110145154688](/images/rmi-registry-security-problem-20200206/image-20200110145154688.png)

接下来，远程bind对象将构造好的remote对象传过去即可，来看一下这个代码

![image-20200110145346319](/images/rmi-registry-security-problem-20200206/image-20200110145346319.png)

## 0x03 攻击Registry jdk<8u232_b09

jdk8u121修复后的版本里，对反序列化的类做了白名单限制，见`sun/rmi/registry/RegistryImpl.java#registryFilter`

这个白名单包括：

```java
if (String.class == clazz
        || java.lang.Number.class.isAssignableFrom(clazz)
        || Remote.class.isAssignableFrom(clazz)
        || java.lang.reflect.Proxy.class.isAssignableFrom(clazz)
        || UnicastRef.class.isAssignableFrom(clazz)
        || RMIClientSocketFactory.class.isAssignableFrom(clazz)
        || RMIServerSocketFactory.class.isAssignableFrom(clazz)
        || java.rmi.activation.ActivationID.class.isAssignableFrom(clazz)
        || java.rmi.server.UID.class.isAssignableFrom(clazz)) {
    return ObjectInputFilter.Status.ALLOWED;
} else {
    return ObjectInputFilter.Status.REJECTED;
}
```

0x02中发送的对象是代理后的AnnotationInvocationHandler对象，并不在上述允许的类里面，这导致原先ysoserial工具中的ysoserial.exploit.RMIRegisterExploit无法利用。这里我们参考[3](http://www.codersec.net/2018/09/一次攻击内网rmi服务的深思/)的方法来达成利用。

首先思路比较明确的是，如果要绕过这个限制，我们需要在上述的白名单里找到可以利用的对象。

在白名单里我们注意一下两个特殊对象Remote对象和UnicastRef对象

### 1. UnicastRef对象

我们都知道RMI过程中存在客户端与服务器端之间的交互，那么在代码层面，我们需要怎么去创造这样一个链接呢？

由于漏洞发生点为向远程服务器注册对象的引用。回顾一下，我们在bind时，会先去获得一个Registry，类似下面

```java
Registry registry = LocateRegistry.getRegistry("192.168.98.80");
```

跟进`java/rmi/registry/LocateRegistry.java#getRegistry`

![image-20200131185848839](/images/rmi-registry-security-problem-20200206/image-20200131185848839.png)

注意到这样一段代码，通过TCPEndpoint注册服务端的host、端口等信息，以UnicastRef封装liveRef.在下面createProxy时使用了RemoteObjectInvocationHandler作为UnicastRef动态代理的处理类

![image-20200131191232156](/images/rmi-registry-security-problem-20200206/image-20200131191232156.png)

最终，我们将以客户端的身份去链接，所以这里的Registry会是`sun/rmi/registry/RegistryImpl_Stub.java#bind`向远程RMI Registry注册。

![image-20200131231355987](/images/rmi-registry-security-problem-20200206/image-20200131231355987.png)

newCall发起连接，并将需要绑定的对象发送过去。

到这里就结束了向远程Registry发起绑定的操作。这个过程中我们用到了UnicastRef对象，那么这里想象一下，如果我们可以控制UnicastRef对象里LiveRef的host和port，那么我们就能发起任意的RMI连接。这里就是ysoserial中JRMPClient的原理，来看一下这个payload

![image-20200131232428711](/images/rmi-registry-security-problem-20200206/image-20200131232428711.png)

是不是很熟悉XD，使用的方法就是前面绑定过程中的代码。而在白名单里UnicastRef对象是允许被反序列化的。

### 2. RemoteObjectInvocationHandler对象

前面分析到UnicastRef可被用于发起RMI连接，但是为了符合发送的条件，仍然需要满足实现Remote接口的条件。而UnicastRef并没有实现Remote接口，这就意味着直接传UnicastRef是不行的，我们还需要再多做一步，这里有两种方法：

1. 跟RMIRegisterExploit一样，使用Proxy反射来实现，其handler继承于Remote并处理了构造好的UnicastRef，这里用到的就是RemoteObjectInvocationHandler
2. 找到一个可以封装UnicastRef的对象，并且该对象还实现了Remote对象

这里JRMPClient使用的RemoteObjectInvocationHandler就是第一种方法，我们将AnnotationInvocationHandler替换成RemoteObjectInvocationHandler。在反序列化时会调用RemoteObjectInvocationHandler的父类RemoteObject的readObject函数

![image-20200110220005786](/images/rmi-registry-security-problem-20200206/image-20200110220005786.png)

这里的ref就是我们传进去的UnicastRef，调用其readExternal函数，这里介绍一下readExternal

> Java默认的序列化机制非常简单，而且序列化后的对象不需要再次调用构造器重新生成，但是在实际中，我们可以会希望对象的某一部分不需要被序列化，或者说一个对象被还原之后，其内部的某些子对象需要重新创建，从而不必将该子对象序列化。 在这些情况下，我们可以考虑实现Externalizable接口从而代替Serializable接口来对序列化过程进行控制。
> Externalizable接口extends Serializable接口，而且在其基础上增加了两个方法：writeExternal()和readExternal()。这两个方法会在序列化和反序列化还原的过程中被自动调用，以便执行一些特殊的操作。
>
> https://xz.aliyun.com/t/5392

这里的readExternal就是重新创建一个tcp连接

![image-20200110220105735](/images/rmi-registry-security-problem-20200206/image-20200110220105735.png)

继续往下跟

![image-20200110220150019](/images/rmi-registry-security-problem-20200206/image-20200110220150019.png)

重新生成一个LiveRef对象后，将存储到当前的ConnectionInputStream上。后续该stream会继续调用registerRefs函数

![image-20200110220710690](/images/rmi-registry-security-problem-20200206/image-20200110220710690.png)

最终由DGCClient发起连接，下图中的loopup函数

![image-20200110220823670](/images/rmi-registry-security-problem-20200206/image-20200110220823670.png)

到这里后面就是JRMPListener反序列化的东西了，这里在最后进行分析。

### 3. RMIConnectionImpl_Stub对象

前面提到了两种思路，还有一种就是找到一个实现了Remote接口并且封装了ref的对象，这里RMIConnectionImpl_Stub对象就是

RemoteObjectInvocationHandler后续的触发主要依靠RemoteObject对象的readObject函数的重新填充，而RMIConnectionImpl_Stub对象也继承了RemoteObject所以后面的一些调用过程跟第二个对象一样，不再叙述。

其实顺着思路找还能发现`DGCImpl_Stub`、`RMIServerImpl_Stub`、`RegistryImpl_Stub`、`ReferenceWrapper_Stub`都可以

### 20200616 更新一个小trick

前面2的部分提到了由于UnicastRef的反序列化，还原的内容ref会被注册到当前的ConnectionInputStream的incomingRefTable，并于StreamRemoteCall的releaseInputStream时调用发起反向jrmp链接。

这里的重点在于UnicastRef的反序列化，我们在3的部分找的那几个类都是因为封装UnicastRef，在实际反序列化的过程中，这几个类的属性被调用反序列化而还原UnicastRef。

在常见的readObject函数的处理中，其实有一点很重要，他是一个递归反序列化的过程，就算当前类不存在，但是还是会去递归反序列化当前数据中的类属性。

所以我们也可以不用前面找到的几个类，自己写一个封装UnicastRef也能同样达到这种效果，具体看[RMIConnectWrapped](https://github.com/wh1t3p1g/ysomap/blob/master/core/src/main/java/ysomap/core/payload/java/rmi/RMIConnectWrapped.java)

## 0x04 后续 jdk>=8u232_b09

jdk版本8u232_b09修复了前面使用反向发起JRMP连接的利用。修复点包括两个

### 一：RegistryImpl_Skel

`sun.rmi.registry.RegistryImpl_Skel#dispatcher`，这里截了lookup函数的处理，bind/rebind函数的处理是一样的

![image-20200512145332476](/images/rmi-registry-security-problem-20200206/image-20200512145332476.png)

当发生反序列化错误或者类型转换错误时，会调用`call.discardPendingRefs`，将现有的JRMP连接清除掉。也就意味着这里我们无法用JRMP反向链接的方式来达成利用了。

### 二：DGCImpl_Stub

当Registry处理JRMP反连的时候，会调用`DGCImpl_Stub#dirty`，而`ref.invoke`会最终调用`sun.rmi.transport.StreamRemoteCall#executeCall`来处理返回的异常，这里会最终导致反序列化(详细见0x05番外)

![image-20200512145824806](/images/rmi-registry-security-problem-20200206/image-20200512145824806.png)

而在232版本，将原本在后面注册的`leaseFilter`提到了前面

![image-20200512150213665](/images/rmi-registry-security-problem-20200206/image-20200512150213665.png)

看看该过滤器的限制`sun/rmi/transport/DGCImpl_Stub.java#leaseFilter`

![image-20200118182504042](/images/rmi-registry-security-problem-20200206/image-20200118182504042.png)

对于返回的序列化对象，只允许上面的几种类型，而现有的反序列化利用链中HashSet、HashTable等类都是通不过的。

所以在Registry发起的反向连接是无法利用成功的。

ps:这里用的`DGCImpl_Stub`是客户端发起时使用的，相对应的还有server端接收Client发起的连接的处理`DGCImpl_Skel`，skel这里也存在反序列化漏洞，具体见0x08

## 0x05 番外：ysoserial中的JRMPListener与JRMPClient

看了上面可能你会疑惑，为什么server端发起一个RMI的连接就会触发java反序列化？

前文我们将的是RMI Registry在接收远程绑定对象时所发生的反序列化漏洞，那么RMI Client在接收Server端的数据时是否也会发生反序列化漏洞呢？答案是肯定的，毕竟RMI交互过程中的数据采用的是序列化的数据，也就意味着存在着一个反序列化的过程。

看一下JRMPListener的代码，简单来说，其实现了与RMI Client的交互流程。这里我们直接看重点的代码

![image-20200202161819982](/images/rmi-registry-security-problem-20200206/image-20200202161819982.png)

在完成前面的一些交互步骤后，Listener会向Client发送一个ExceptionalReturn的状态，并将序列化的payload填充到BadAttributeValueExpException的val属性。这里用的BadAttributeValueExpException并不是我们以前分析时做的toString触发点，而是仅作为payload的一个载体，在反序列化BadAttributeValueExpException的val属性时同样反序列化了我们的payload。

而位于Client在接收到ExceptionalReturn时的处理方式见`sun/rmi/transport/StreamRemoteCall.java#executeCall`前面的分析都省略了

![image-20200202163234429](/images/rmi-registry-security-problem-20200206/image-20200202163234429.png)

在这里我们看到了熟悉的readObject函数，其用于将前面的Exception进行反序列化。

到这里就可以串起来了，Client发起RMI连接，连接到我们的恶意Listener上面。而我们的Listener将返回一个构造好的Exception，旨在Client接收到ExceptionalReturn的信号时进行还原，从而造成了RMI Client端也受到反序列化漏洞的攻击。

## 0x06 总结

前文主要讲诉了RMI的相关反序列化问题，包括RMI Registry和RMI Client接收到反序列化数据时产生的反序列化漏洞。

全文所使用的JDK版本为JDK8，在分析过程中，发现在最近的JDK8u版本上，已无法对RMI Registry发起攻击，但其在JDK8u232_b09之前的版本还是可以的。

本文主要攻击的是RMI Registry，而RMI的攻击面不单单文中提到的这种方式，还存在

1. 针对codebase的攻击见https://github.com/vulhub/vulhub/blob/master/java/rmi-codebase/README.md，加载我们构造好的class。当然现在这种情况比较少了。
2. 针对绑定的危险obj的攻击，我们可以通过list所有绑定的obj，查找危险的绑定地址进行攻击。这里的危险怎么定义呢？第一是绑定的对象确实存在操作系统命令等；第二是该对象的类函数参数中存在反序列化点，比如hello(HashTable xxx)，其中的HashTable是CommonsCollections7的触发点，在传递过程中，xxx会被序列化，到了RMI Server时会反序列化，也就执行了我们的payload。最后，这里暂时还没找到案例...

## 0x07 20200303更新 UnicastRemoteObject Gadget

这个Gadget的来源是https://mogwailabs.de/blog/2020/02/an-trinhs-rmi-registry-bypass/

经过测试，这个Gadget可以做到跟JRMPClient一样的效果，但是无法跟上面的Level2一样绕过限制，原因看下面

本地在bind或rebind一个Remote对象时，会在sun/rmi/server/MarshalOutputStream.java#replaceObject进行转化

![image-20200303203244913](/images/rmi-registry-security-problem-20200206/image-20200303203244913.png)

![image-20200303203931864](/images/rmi-registry-security-problem-20200206/image-20200303203931864.png)

原来的对象会被转化成上面的一个结构，这里直接丢掉了UnicastRemoteObject，自然在Registry端无法从UnicastRemoteObject的readObject函数开始，这样这个Gadget就无法成功利用了。

要想利用这个链来绕过限制，我们可能得自己写一个bind的过程才可以，把getTarget的过程去掉直接发过去。这个Gadget利用价值比较低XD

ps：貌似可以通过重写的方式来解决这个问题，这里有空再分析XD

### 20200617 更新UnicastRemoteObject Gadget

前面在做分析时，发现在使用这个利用链的时候，在发过去之前就会被替换UnicastRef的问题，导致我们发到Registry后无法还原出正确的jrmp，今天来看看他是怎么替换的

`java.io.ObjectOutputStream#writeObject0#1143`

```java
if (enableReplace) {
  Object rep = replaceObject(obj);
  if (rep != obj && rep != null) {
    cl = rep.getClass();
    desc = ObjectStreamClass.lookup(cl, true);
  }
  obj = rep;
}
```

从`call.getOutputStream()`获取到的outputstream在写入具体的object时，后续会执行到前面的代码上，判断是否需要enableReplace（默认是true），所以会默认走到我在3月份时分析的地方，把我们想要的jrmp连接给替换掉了。

所以解决这个问题的方案就是将这个enableReplace给置为false，这里实现起来就比较简单了，我们可以直接对outputstream做反射调用，替换true为false，具体实现见[L34](https://github.com/wh1t3p1g/ysomap/blob/master/core/src/main/java/ysomap/core/exploit/rmi/component/Naming.java#L34)

这里需要提一点的是这条链巧妙之处在于

1. UnicastRemoteObject利用链用到的对象都是在Registry可反序列化的白名单里的
2. 跟前面几个封装unicastref的思路不同，UnicastRemoteObject实际上是主动向外发出jrmp连接的方式，而不是前面通过incomingtable表的方式去触发jrmp连接

为什么说他巧妙呢？在>=8u232_b09版本存在两个限制（具体见0x04）

1. 消除了封装unicastRef的威胁
2. 在DGC层添加了白名单的方式，导致就算jrmp能反链也不能反序列化出白名单之外的类

而UnicastRemoteObject绕过了上面的两个限制

1. 首先对于第一个限制，UnicastRemoteObject的jrmp反连发生在readObject过程中

   ![image-20200617230402963](/images/rmi-registry-security-problem-20200206/image-20200617230402963.png)

2. 其次对于第二个限制，前面提到Registry能触发JRMP反连主要是因为调用了`DGCClient.registerRefs`去处理

   而过这个点就需要受到前面提到的DGC白名单的问题。怎么绕过这个地方？简单的就是找一个不经过DGCClient来触发即可。

   前面分析<8u232_b09时，用到的RemoteObjectInvocationHandler的方式来触发，不过这里其实只用到了封装UnicastRef的作用（这里提一下实际触发时需要调用UnicastRef.invoke）。UnicastRemoteObject对这个handler做了更深入的利用，这里用到了`java.rmi.server.RemoteObjectInvocationHandler#invokeRemoteMethod`

   ![image-20200617234429050](/images/rmi-registry-security-problem-20200206/image-20200617234429050.png)

   调用了`ref.invoke`触发jrmp反连，到这里都没有经过DGCClient的路径，自然也就没有白名单的限制。

不过这条链到了8u242也失效了，主要原因在于lookup接口无法再反序列化非string类型的object了

![image-20200618002342127](/images/rmi-registry-security-problem-20200206/image-20200618002342127.png)

## 0x08 RMI DGC实现问题(ysoserial.expliots.JRMPClient)

在JEP290之前，RMI的DGCImpl_skel#dipatch接收处，获取到数据后，直接readObject造成的。

![image-20200306202106633](/images/rmi-registry-security-problem-20200206/image-20200306202106633.png)

在JEP290之后，反序列化前做了校验，见DGCImpl

![image-20200306202539911](/images/rmi-registry-security-problem-20200206/image-20200306202539911.png)

![image-20200306202604696](/images/rmi-registry-security-problem-20200206/image-20200306202604696.png)

导致了ysoserial的exploit中的JRMPClient失效

## 0x09 总结中第二种方式的触发点（20200317 更新）

前面总结中提到的第二中方式：通过寻找可以利用的绑定对象的函数的参数进行反序列化利用

直接讲触发点`sun/rmi/server/UnicastServerRef.java#dispatch#338`

![image-20200317203347230](/images/rmi-registry-security-problem-20200206/image-20200317203347230.png)

当我们编写Client端对Server端挂载的对象进行远程函数调用（RMI）时，Server端会逐一进行（获取到Methtod，解析parameters，最后进行invoke调用）。而在解析params时（我们讲过RMI过程中，对象均是序列化的状态）我们需要先对参数对象进行反序列化，也就是第338行所做的工作，继续往下跟

![image-20200317203723497](/images/rmi-registry-security-problem-20200206/image-20200317203723497.png)

在函数`unmarshalParametersUnchecked`中分别对每个参数进行反序列化还原

![image-20200317203838431](/images/rmi-registry-security-problem-20200206/image-20200317203838431.png)

如果所接受的类型非基础数据结构，那么将直接调用readObject，这部分并没有前面filter的限制

所以如果找到了一个Server端挂载的对象存在函数参数类型为Object、HashTable等类型时，我们可以直接穿入构造好的反序列化利用链。当前前提还是Server端的环境中存在相应的反序列化利用链的依赖。

