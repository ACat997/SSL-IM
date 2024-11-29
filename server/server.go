package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"io/ioutil"
	"log"
	"net"

	"github.com/ACat997/SSL-IM/db"
)

func main() {
	// 初始化数据库
	password := "securepassword"
	database, err := db.InitDB(password)
	if err != nil {
		log.Fatalf("数据库初始化失败: %v", err)
	}
	defer database.Close()

	// 加载服务器证书
	serverCert, err := tls.LoadX509KeyPair("server/server.crt", "server/server.key")
	if err != nil {
		log.Fatalf("加载服务器证书失败: %v", err)
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
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	// 启动 TLS 监听
	listener, err := tls.Listen("tcp", ":8443", tlsConfig)
	if err != nil {
		log.Fatalf("TLS 监听失败: %v", err)
	}
	defer listener.Close()

	log.Println("服务器已启动，等待客户端连接...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接受连接失败: %v", err)
			continue
		}

		go handleConnection(conn, database)
	}
}

func handleConnection(conn net.Conn, database *sql.DB) {
	defer conn.Close()
	log.Printf("客户端已连接: %s", conn.RemoteAddr())

	for {
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			log.Printf("读取失败: %v", err)
			return
		}

		message := string(buffer[:n])
		log.Printf("收到消息: %s", message)

		// 保存消息到数据库
		db.SaveMessage(database, message)

		conn.Write([]byte("已收到: " + message))
	}
}
