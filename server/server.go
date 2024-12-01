package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"

	"github.com/ACat997/SSL-IM/db"
)

func main() {
	// 初始化数据库
	password := "securepassword"
	database, err := db.InitDB(password)
	if err != nil {
		log.Fatalf("init db err: %v", err)
	}
	defer database.Close()

	// 加载服务器证书
	serverCert, err := tls.LoadX509KeyPair("server/server.crt", "server/server.key")
	if err != nil {
		log.Fatalf("load server crt err: %v", err)
	}

	// 加载 CA 证书
	caCert, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		log.Fatalf("load ca err: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// 配置 TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,                     // 客户端证书验证
		ClientAuth:   tls.RequireAndVerifyClientCert, // 强制验证客户端证书
	}

	// 启动 TLS 监听
	listener, err := tls.Listen("tcp", ":8443", tlsConfig)
	if err != nil {
		log.Fatalf("listen tls err: %v", err)
	}
	defer listener.Close()

	log.Println("服务器已启动，等待客户端连接...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("recieve conn err: %v", err)
			continue
		}

		go handleConnection(conn, database, password)
	}
}

func handleConnection(conn net.Conn, database *sql.DB, encryptionKey string) {
	defer conn.Close()
	log.Printf("client connected: %s", conn.RemoteAddr())

	// 创建一个通道用于服务端主动发送消息
	messageChan := make(chan string)

	// 启动 Goroutine 监听通道并发送消息给客户端
	go func() {
		for {
			select {
			case msg := <-messageChan:
				_, err := conn.Write([]byte(msg))
				if err != nil {
					log.Printf("send message failed: %v", err)
					return
				}
				db.SaveEncryptedMessage(database, msg, encryptionKey)
			}
		}
	}()

	// go协程接收客户端消息
	go func() {
		for {
			buffer := make([]byte, 1024)
			n, err := conn.Read(buffer)
			if err != nil {
				log.Printf("recieve message failed : %v", err)
				return
			}
			message := string(buffer[:n])
			log.Printf("%s\n", message)
			// 保存消息到数据库
			db.SaveEncryptedMessage(database, message, encryptionKey)
		}
	}()

	// 主进程可以向客户端发消息
	reader := bufio.NewReader(os.Stdin)
	for {
		serverMessage, _ := reader.ReadString('\n')
		serverMessage = strings.TrimSpace(serverMessage)
		if serverMessage != "ls log" {
			messageChan <- "server:" + serverMessage
		} else {
			fmt.Print("please enter password: ")
			password, _ := reader.ReadString('\n')
			password = strings.TrimSpace(password)
			logs, err := db.GetDecryptedChatLogs(database, password)
			if err != nil {
				log.Printf("get logs err : %v", err)
			} else {
				for _, v := range logs {
					log.Printf("%s", v)
				}
			}
		}
	}
}
