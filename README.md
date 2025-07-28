# ZJUCTFTools

ZJUCTFTools 是一个用于连接 [ZJUCTF](https://ctf.zjusec.com/) 平台容器题目的轻量级 WebSocket 到 TCP 转发代理。

自动登录浙江大学 WebVPN，建立本地 TCP 到容器题目的 WebSocket 隧道，可以直接使用本地端口访问题目服务，无需手动配置代理或使用 websocat 等工具。

参考：[https://courses.zjusec.com/2024/extra/proxy/](https://courses.zjusec.com/2024/extra/proxy/)

WebVPN 实现：[https://github.com/eWloYW8/ZJUWebVPN](https://github.com/eWloYW8/ZJUWebVPN)

## Installation

### [Release](https://github.com/eWloYW8/ZJUCTFTools/releases)



### Build from source

```bash
git clone https://github.com/eWloYW8/ZJUCTFTools
cd ZJUCTFTools

go mod tidy
go build
```

## Usage

```
Usage of ZJUCTFTools:
  -container-id string
        ZJUCTF container ID (for example: ec45c945-9352-4d27-aba5-549368d35896)
  -listen-host string
        Listen host (default "127.0.0.1")
  -listen-port int
        Listen port (default 20123)
  -password string
        ZJU WebVPN password
  -username string
        ZJU WebVPN username
```

### Example
```bash
./ZJUCTFTools \
  --container-id <容器ID> \
  --username <你的学号> \
  --password <你的 WebVPN 密码> \
  --listen-host 127.0.0.1 \
  --listen-port 61234
```