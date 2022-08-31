---
title: thinkphp v6.0.x 反序列化利用链挖掘
tags: 
  - 漏洞分析
categories: codereview
date: 2019-09-10 12:59:00
---
## 0x00 前言

上一篇分析了tp 5.2.x的反序列化利用链挖掘，顺着思路，把tp6.0.x也挖了。有类似的地方，也有需要重新挖掘的地方。
<!-- more -->

## 0x01 环境准备

采用composer安装6.0.*-dev版本

```
composer create-project topthink/think=6.0.x-dev v6.0
```

## 0x02 利用链分析

### 背景回顾

拿到v6.0.x版本，简单的看了一下，有一个好消息和一个坏消息。

好消息是5.2.x版本函数动态调用的反序列化链后半部分，还可以利用。

坏消息是前面5.1.x，5.2.x版本都基于触发点`Windows`类的`__destruct`,好巧不巧的是6.0.x版本取消了`Windows`类。这意味着我们得重新找一个合适的起始触发点，才能继续使用上面的好消息。

### vendor/topthink/think-orm/src/Model.php 新起始触发点

为了节省篇幅，后文不再重复介绍触发`__toString`函数后的利用链，这部分同5.2.x版本相同(不过wonderkun师傅的利用链已失效，动态函数调用的利用链还能用)。

通常最好的反序列化起始点为`__destruct`、`__wakeup`，因为这两个函数的调用在反序列化过程中都会自动调用，所以我们先来找此类函数。这里我找了`vendor/topthink/think-orm/src/Model.php`的`__destruct`函数。

```php
public function __destruct()
{
    if ($this->lazySave) {// 构造lazySave为true，进入save函数
        $this->save();
    }
}

public function save(array $data = [], string $sequence = null): bool
{
  // ...
  if ($this->isEmpty() || false === $this->trigger('BeforeWrite')) {
    return false;
  }

  $result = $this->exists ? $this->updateData() : $this->insertData($sequence);
  // ...
}
```

首先构造`lazySave`的值为`true`,从而进入`save`函数。

这次触发点位于`updateData`函数内，为了防止前面的条件符合，而直接return，我们首先需要构造相关参数

```php
public function isEmpty(): bool
{
    return empty($this->data);
}

protected function trigger(string $event): bool
{
  if (!$this->withEvent) {
    return true;
  }
  // ...
```

其中需保证`isEmpty`返回`false`，以及`$this->trigger('BeforeWrite')`返回`true`

1. 构造`$this->data`为非空数组
2. 构造`$this->withEvent`为`false`
3. 构造`$this->exists`为`true`

从而进入我们需要的`updateData`函数，来看一下该函数内容

```php
protected function updateData(): bool
{
    // 事件回调
    if (false === $this->trigger('BeforeUpdate')) {// 此处前面已符合条件
        return false;
    }

    // ...

    // 获取有更新的数据
    $data = $this->getChangedData();

    if (empty($data)) {
        // 关联更新
        if (!empty($this->relationWrite)) {
            $this->autoRelationUpdate();
        }
        return true;
    }
		// ...
    // 检查允许字段
    $allowFields = $this->checkAllowFields(); // 触发__toString
```

同样的，为了防止提前`return`，需要符合`$data`非空，来看一下`getChangedData`

```php
public function getChangedData(): array
{
    $data = $this->force ? $this->data : array_udiff_assoc($this->data, $this->origin, function ($a, $b) {
        if ((empty($a) || empty($b)) && $a !== $b) {
            return 1;
        }

        return is_object($a) || $a != $b ? 1 : 0;
    });

    // ...

    return $data;
}
```

这里我们可以强行置`$this->force`为`true`，直接返回我们前面构造的非空`$this->data`

这样，我们就成功到了调用`checkAllowFields`的位置

```php
protected function checkAllowFields(): array
{
    // 检测字段
    if (empty($this->field)) {
        if (!empty($this->schema)) {
            $this->field = array_keys(array_merge($this->schema, $this->jsonType));
        } else {
            $query = $this->db();// 最终的触发__toString的函数
            $table = $this->table ? $this->table . $this->suffix : $query->getTable();

            $this->field = $query->getConnection()->getTableFields($table);
        }

        return $this->field;
    }
		// ...
}
```

同样，为了到`$this->db()`函数的调用，需要

1. 构造`$this->field`为空
2. 构造`$this->schema`为空

其实这两个地方不需要构造，默认都为空

最终，我们终于到了可以触发`__toString`的位置

```php
public function db($scope = []): Query
{
    /** @var Query $query */
    $query = self::$db->connect($this->connection)
        ->name($this->name . $this->suffix)// toString
        ->pk($this->pk);
```

看到熟悉的字符串拼接了嘛！！！

不过为了达到该出拼接，我们还是得首先满足`connect`函数的调用。此处代码就不说了，置`$this->connection`为`mysql`即可。接下来，不管是设`$this->name`还是`$this->suffix`为最终的触发`__toString`的对象，都会有同样的效果。

后续的思路，就是原来`vendor/topthink/think-orm/src/model/concern/Conversion.php`的`__toString`开始的利用链，不在叙述。

我把exp集成到了[phpggc](https://github.com/wh1t3p1g/phpggc)上，使用如下命令即可生成

```bash
./phpggc -u ThinkPHP/RCE2 'phpinfo();'
```

这里由于用到了SerializableClosure，需要使用编码器编码，不可直接输出拷贝利用。

