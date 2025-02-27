package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// ProxyConfig 代理配置结构体
type ProxyConfig struct {
	XMLName       xml.Name       `xml:"config"`
	DefaultProxy  ProxyRule      `xml:"defaultProxy"`
	ProxyRules    []ProxyRule    `xml:"proxy"`
	DirectDomains []string       `xml:"directDomains>domain"`
	CustomHeaders []CustomHeader `xml:"customHeaders>header"`
}

type CustomHeader struct {
	Domain      string `xml:"domain,attr"`
	PathPrefix  string `xml:"pathPrefix,attr"`
	HeadersPath string `xml:"headersPath,attr"`
}

// ProxyRule 单个代理规则
type ProxyRule struct {
	Domain   string `xml:"domain,attr,omitempty"`
	ProxyURL string `xml:"proxyUrl,attr"`
	Username string `xml:"username,attr,omitempty"`
	Password string `xml:"password,attr,omitempty"`
}

var config ProxyConfig
var serverHost string
var serverPort int

func loadConfig(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %v", err)
	}

	err = xml.Unmarshal(data, &config)
	if err != nil {
		return fmt.Errorf("解析XML配置失败: %v", err)
	}

	log.Printf("成功加载配置，共 %d 条代理规则", len(config.ProxyRules))
	log.Printf("直连域名数量: %d", len(config.DirectDomains))
	if config.DefaultProxy.ProxyURL != "" {
		log.Printf("默认代理: %s", config.DefaultProxy.ProxyURL)
	} else {
		log.Printf("默认代理: 无")
	}
	return nil
}

func isDirect(domain string) bool {
	for _, d := range config.DirectDomains {
		if strings.Contains(domain, d) {
			return true
		}
	}
	return false
}

func findProxyRule(domain string) *ProxyRule {
	// 检查是否在直连列表中
	if isDirect(domain) {
		return nil // 直连
	}

	// 查找特定域名代理规则
	for _, rule := range config.ProxyRules {
		if strings.Contains(domain, rule.Domain) {
			return &rule
		}
	}

	// 如果没有匹配规则且有默认代理，返回默认代理
	if config.DefaultProxy.ProxyURL != "" {
		return &config.DefaultProxy
	}

	return nil // 没有代理规则，直连
}

// 处理重定向URL，将其转换为通过代理服务器的URL
func handleRedirectURL(redirectURL string) string {
	if redirectURL == "" {
		return ""
	}

	// 如果已经是相对路径，不需要处理
	if !strings.HasPrefix(redirectURL, "http://") && !strings.HasPrefix(redirectURL, "https://") {
		return redirectURL
	}

	// 构建新的重定向URL，指向我们的代理服务器
	return fmt.Sprintf("http://%s:%d/%s", serverHost, serverPort, redirectURL)
}

// 修正URL格式问题
func fixTargetURL(path string) string {
	// 修复URL中的双斜杠问题 (https:/www.example.com -> https://www.example.com)
	re := regexp.MustCompile(`^(https?:/)([^/])`)
	if re.MatchString(path) {
		path = re.ReplaceAllString(path, "$1/$2")
	}

	// 确保URL以http://或https://开头
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		// 尝试推断协议
		if strings.HasPrefix(path, "www.") {
			path = "http://" + path
		} else {
			// 默认假设为http
			path = "http://" + path
		}
	}

	return path
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	// 解析目标URL
	targetPath := r.URL.Path[1:] // 移除开头的'/'

	// 处理请求参数
	if r.URL.RawQuery != "" {
		targetPath = targetPath + "?" + r.URL.RawQuery
	}

	// 修正URL格式问题
	targetPath = fixTargetURL(targetPath)

	targetURL, err := url.Parse(targetPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("无法解析目标URL: %v", err), http.StatusBadRequest)
		return
	}

	// 查找域名对应的代理规则
	proxyRule := findProxyRule(targetURL.Host)

	// 创建客户端，禁用自动重定向，我们需要自己处理
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 不自动重定向，返回http.ErrUseLastResponse使客户端返回最后一个响应
			return http.ErrUseLastResponse
		},
	}

	// 如果找到代理规则并且设置了代理URL
	if proxyRule != nil && proxyRule.ProxyURL != "" {
		proxyURL, err := url.Parse(proxyRule.ProxyURL)
		if err != nil {
			http.Error(w, fmt.Sprintf("代理URL配置错误: %v", err), http.StatusInternalServerError)
			return
		}

		// 设置代理认证
		if proxyRule.Username != "" && proxyRule.Password != "" {
			proxyURL.User = url.UserPassword(proxyRule.Username, proxyRule.Password)
		}

		transport := &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
		client.Transport = transport
		log.Printf("使用代理 %s 访问 %s", proxyRule.ProxyURL, targetURL.String())
	} else {
		log.Printf("直接访问 %s (不使用代理)", targetURL.String())
	}

	// 创建请求
	req, err := http.NewRequest(r.Method, targetPath, r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("创建请求失败: %v", err), http.StatusInternalServerError)
		return
	}

	for _, i := range config.CustomHeaders {
		if i.Domain == targetURL.Host && strings.HasPrefix(targetURL.Path, i.PathPrefix) {
			addHeadersFromTxt(i.HeadersPath, req)
			break
		}
	}

	// 复制原始请求的头信息
	for key, values := range r.Header {
		// 跳过一些特定的头，这些可能会导致问题
		if key == "Host" || key == "Connection" || key == "Content-Length" {
			continue
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// 设置X-Forwarded-For头
	req.Header.Set("X-Forwarded-For", r.RemoteAddr)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("代理请求失败: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// 检查是否是重定向响应
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" {
			// 处理重定向URL
			newLocation := handleRedirectURL(location)
			resp.Header.Set("Location", newLocation)
			log.Printf("重定向: %s -> %s", location, newLocation)
		}
	}

	// 复制响应头
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// 设置状态码
	w.WriteHeader(resp.StatusCode)

	// 复制响应体
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("复制响应体失败: %v", err)
	}
}

func addHeadersFromTxt(path string, req *http.Request) {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Println(err)
		return
	}
	bs := bytes.Split(b, []byte("\n"))
	for _, row := range bs[1:] {
		b, a, found := bytes.Cut(row, []byte(":"))
		if found {
			key := string(bytes.Trim(b, " \n\r"))
			lkey := strings.ToLower(key)
			if lkey == "content-length" || lkey == "transfer-encoding" {
				continue
			}
			req.Header.Add(key, string(bytes.Trim(a, " \n\r")))
		}
	}
}

func main() {
	// 设置服务器信息
	serverHost = "localhost"
	serverPort = 3000

	// 加载配置文件
	if err := loadConfig("proxy_config.xml"); err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	// 注册处理函数
	http.HandleFunc("/", proxyHandler)

	// 启动服务器
	log.Printf("代理服务器启动在 http://%s:%d", serverHost, serverPort)
	log.Printf("使用示例: http://%s:%d/https://baidu.com/search", serverHost, serverPort)
	err := http.ListenAndServe(fmt.Sprintf(":%d", serverPort), nil)
	if err != nil {
		log.Fatalf("服务器启动失败: %v", err)
	}
}
