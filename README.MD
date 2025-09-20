# TinyACME

Tiny ACME is a ***working subset*** of RFC 8555 protocol implementation in a single go file.  
It is designed to be small, simple, and easy to integrate into existing projects.   
It is not a full-featured ACME client, but it can be used to obtain and renew TLS certificates from Let's Encrypt.

## Why

'Cause I don't f-ing care about most pare of the ACME protocol.  
What I need is a darned TLS client and just give me that!

## How

`tinyacme <your domain/ip>`  
Make sure that your 80 port is not occupied.

# TinyACME

TinyACME是RFC8555的子集实现，它只使用了Go系统库（含x），并且只有一个文件。  
它被设计为简单，易于集成到现有项目中。  
它不是一个功能齐全的ACME客户端，但它可以用来从Let's Encrypt获取TLS证书。

## 为什么

因为我只关心怎么用ACME搞免费证书。  
扯那么多唧唧歪歪的干什么。

## 怎么用

`tinyacme <你的域名/ip>`  
请确保80端口没有被占用。
