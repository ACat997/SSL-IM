package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

func main() {
	// 加载客户端证书
	clientCert, err := tls.LoadX509KeyPair("client/client.crt", "client/client.key")
	if err != nil {
		log.Fatalf("load client crt err: %v", err)
	}

	// 客户端加载证书和根证书
	caCert, err := ioutil.ReadFile("ca.crt") // 读取 CA 根证书
	if err != nil {
		log.Fatalf("load ca failed: %v", err)
	}

	// 创建新的证书池并将 CA 根证书添加到证书池中
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// 配置 TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert}, // 客户端证书
		RootCAs:      caCertPool,                    // 加载 CA 证书池
		ServerName:   "localhost",                   // 验证服务端证书的 SAN
	}

	// 创建 TLS 连接
	conn, err := tls.Dial("tcp", "localhost:8443", tlsConfig)
	if err != nil {
		log.Fatalf("conn failed : %v", err)
	}
	defer conn.Close()

	log.Println("connected")

	// 启动 Goroutine 监听服务器消息
	go func() {
		for {
			buffer := make([]byte, 1024)
			n, err := conn.Read(buffer)
			if err != nil {
				log.Printf("recieve server message err: %v", err)
				return
			}
			fmt.Printf("%s\n", string(buffer[:n]))
		}
	}()

	// 主线程处理用户输入
	reader := bufio.NewReader(os.Stdin)
	for {
		message, _ := reader.ReadString('\n')
		message = strings.TrimSpace(message)
		_, err = conn.Write([]byte("client: " + message))
		if err != nil {
			log.Fatalf("client send message err : %v", err)
		}
	}
}
