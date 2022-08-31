---
title: temmoku home版 t1.15 前台sqli
tags: 
  - 漏洞分析
categories: codereview
date: 2019-02-21 21:09:44
---

## 0x00
很久没有审计了，找了个简单的cms审计
这次找的是temmoku，他修改了thinkphp作为他的底层框架。
代码写的很难受，写出来的界面也很难受，所以找了个注入就不想看了，记录一下。

## 0x01 前台注入

这套cms，每个控制器都继承了`temmoku/controller.php`，其中controller构造函数做了相关权限控制
找到`temmoku/controller.php`，定位到__construct函数

```php
function __construct()
{
 $this->_view     =   new view();
    if(!cookie::get('USER_First_Visit')){
      cookie::set('USER_First_Visit',$_SERVER['REQUEST_TIME_FLOAT']);
    }
$lock=APP_PATH.'conf/install.lock';
  if(is_file($lock)){
    if('admin'!=MODULE && 'user'!=MODULE){
      hook_listen('index_power_begin');
    }
    //验证普通会员状态
    $this->User_Check();// 注入

    if('admin'!=MODULE && 'user'!=MODULE){
      hook_listen('index_power_end');
    }

  }
}
```
注意到第13行，调用了User_Check函数，这个函数完成了从cookie中获取到登陆后的加密字串，解密后再查询的操作。
```php
private function User_Check(){
      $ORDINARY_MEMBER=cookie::get('ORDINARY_MEMBER');
      if($ORDINARY_MEMBER){
      if(json_encode($ORDINARY_MEMBER)){
        $ORDINARY_MEMBER=decode($ORDINARY_MEMBER);
        list($uid,$password,$onlineip)=$r =explode(' ',$ORDINARY_MEMBER);
        if(!intval($uid) || !$password || C('ONLINEIP') != $onlineip || !$onlineip){
          cookie::del('ORDINARY_MEMBER');
          return;
        }
        $data = (new lib\user)->Cookie_Login($uid,$password);// TODO 伪造cookie 对password做数据注入
        if('0'===$data['code']){
          $data['UserDB']['thumb'] ? $data['UserDB']['thumb']=get_img_url($data['UserDB']['thumb']) : $data['UserDB']['thumb']='/public/global/images/default.png';
          C('MYDB',$data['UserDB']);
          $group=C('USER_GROUP.'.$data['UserDB']['groupid']);
          $group['setting']=unserialize($group['setting']);
          C('MYGROUP',$group);
        }else{
          cookie::del('ORDINARY_MEMBER');
          return;
        }
      }else{
        cookie::del('ORDINARY_MEMBER');
        return;
      }
    }
}
```
从cookie中获得ORDINARY_MEMBER相关的cookie内容，并交由decode解密，解密出uid,password,onlineip，直接带入到Cookie_Login函数，我们先来看一下这个函数，等会再讲如何构造加密串
```php
public function Cookie_Login($uid,$password){
    $UserDB=$this->select('*')->from(jab."user")->where("uid='$uid' AND password='$password'")->row();
    if($UserDB){
      return array("code"=>'0','text'=>"登录成功",'UserDB'=>$UserDB);
    }else{
      return array("code"=>'21','text'=>"密码错误");
    }
}
```
可以看到函数内第一句，进行了数据库查询，熟悉thinkphp的同学肯定知道where函数拼接参数同样能造成注入，那么问题就是如何构造出password来进行注入了，回到上面提到的decode函数，来看一下函数内容
```php
    /**
     * 解密函数
     * @param string $txt 需要解密的字符串
     * @param string $key 密匙
     * @return string 字符串类型的返回结果
     */
function decode($txt, $key = '', $ttl = 0){
    if (empty($txt)) return $txt;
    if (empty($key)) $key = md5(C('MD5'));
    // ... 后面的相关数学操作无关紧要
}
```
注意到在User_Check函数里调用decode时，并没有指定key，那么默认就是取配置文件中的MD5，其值默认为空，所以知道了key以及对应的加密函数，我们就能自己构造相关内容。
其中还有一个要注意的地方是，我们需要同时构造cookie的键内容和onlineip，只有当cookie中名字对时才能取到，只有当onlineip对时才能进行数据库查询。
先来看第一个，构造cookie名
定位`temmoku/lib/cookie.php`

```php
public static function get($key){
  $key=C('cookie_is_en')=='1' ? 'temmoku_'.md5(C('MD5')."_".$key) : 'temmoku_'.$key;
  return empty($_COOKIE[$key]) ? 0 : $_COOKIE[$key];
}
```
默认cookie_is_en为1，所以是加密的，cookie的名字为`temmoku_+md5("_ORDINARY_MEMBER")`
因为MD5默认为空，这样我们就能推出cookie名为`temmoku_c3daef9b5af4ca25121457287fd0c2ac`
其次我们需要构造onlineip,来看看这个onlineip是怎么获取的
定位`temmoku/app.php`

```php
private static function default_config(){
  // ...
  C('onlineip',getRealIp());// TODO 可伪造Ip
  define('onlineip', getRealIp());
  // ...
}
```
继续向下
```php
function getRealIp(){
  $ip=false;
  if(!empty($_SERVER["HTTP_CLIENT_IP"])){
    $ip = $_SERVER["HTTP_CLIENT_IP"];
  }
  if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
      $ips = explode (", ", $_SERVER['HTTP_X_FORWARDED_FOR']);
    if ($ip) { array_unshift($ips, $ip); $ip = FALSE; }
    for ($i = 0; $i < count($ips); $i++) {
        if (!preg_match ("/^(10│172.16│192.168)./", $ips[$i])) {
            $ip = $ips[$i];
            break;
        }
    }
  }
  return ($ip ? $ip : $_SERVER['REMOTE_ADDR']);
}
```
可以看出用Client-Ip就能伪造，那么现在问题都解决了，可以构造加密串了

## 0x02 构造加密串

```php
<?php
/**
 * Created by PhpStorm.
 * User: wh1t3P1g
 * Date: 2019/2/21
 * Time: 19:48
 */

function decode($txt, $key = '', $ttl = 0){
    ...
}

function encode($txt, $key = ''){
    ...
}

echo encode('1550750916.778 \' 127.0.0.1');
```
得到加密串`iBuikbGflt4lk4LiZ747G7NBIm9uPlLKikooVtsqagnfQIk1NZI0-rW`，直接加在cookie里就能造成系统出现数据库错误

## 0x03 总结
这个漏洞是比较经典的问题，用了加密后，开发者默认认为解密后的字符串是安全的，直接拼接到数据库操作上导致的注入。




