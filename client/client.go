package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
)

func main() {
	// 加载客户端证书
	clientCert, err := tls.LoadX509KeyPair("client/client.crt", "client/client.key")
	if err != nil {
		log.Fatalf("加载客户端证书失败: %v", err)
	}

	// 加载 CA 证书
	caCert, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		log.Fatalf("加载 CA 证书失败: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// 配置 TLS
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: false, // 验证服务器证书
	}

	// 连接服务器
	conn, err := tls.Dial("tcp", "localhost:8443", tlsConfig)
	if err != nil {
		log.Fatalf("连接服务器失败: %v", err)
	}
	defer conn.Close()

	log.Println("已连接到服务器")

	for {
		var message string
		fmt.Print("请输入消息: ")
		fmt.Scanln(&message)

		_, err = conn.Write([]byte(message))
		if err != nil {
			log.Fatalf("发送消息失败: %v", err)
		}

		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			log.Fatalf("读取服务器响应失败: %v", err)
		}

		fmt.Printf("服务器响应: %s\n", string(buffer[:n]))
	}
}
