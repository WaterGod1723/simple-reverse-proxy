# simple-reverse-proxy
## feature
add request custom headers, very simple
## what this
when somw app can not set proxy, but you need proxy; when you need add cookie or other headers for some http request
## how to use
- config server in proxy_config.xml
- go mod init r-proxy
- go run main.go
- server on http://localhost:3000
- do request just like http://localhost:3000/https://www.baidu.com/v1 or http://localhost:3000/https:/www.baidu.com/v1/
