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
	// Initialize database
	password := "securepassword"
	database, err := db.InitDB(password)
	if err != nil {
		log.Fatalf("init db err: %v", err)
	}
	defer database.Close()

	// Load server certificate
	serverCert, err := tls.LoadX509KeyPair("server/server.crt", "server/server.key")
	if err != nil {
		log.Fatalf("load server crt err: %v", err)
	}

	// Load CA certificate
	caCert, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		log.Fatalf("load ca err: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,                     // Client certificate validation
		ClientAuth:   tls.RequireAndVerifyClientCert, // Require and verify client certificates
	}

	// Start TLS listener
	listener, err := tls.Listen("tcp", ":8443", tlsConfig)
	if err != nil {
		log.Fatalf("listen tls err: %v", err)
	}
	defer listener.Close()

	log.Println("🚀 Server started, waiting for client connections...")

	// Main server loop
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("❌ Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(conn, database, password)
	}
}

// startMenu displays the menu and handles user input
func startMenu(database *sql.DB, password string, conn net.Conn) {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("\n=========================")
		fmt.Println("       MAIN MENU         ")
		fmt.Println("=========================")
		fmt.Println("1️⃣  Start Chat with Client")
		fmt.Println("2️⃣  View Chat Logs")
		fmt.Println("0️⃣  Exit")
		fmt.Println("=========================")
		fmt.Print("👉 Please select an option: ")

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			// Chat with server
			chatWithServer(database, password, conn)
		case "2":
			// View chat logs
			viewChatLogs(database, password)
		case "0":
			// Exit
			log.Println("👋 Exiting server... Goodbye!")
			os.Exit(0)
		case "menu":
			// Display menu again
			continue
		default:
			fmt.Println("⚠️ Invalid choice. Please try again.")
		}
	}
}

// chatWithServer handles communication with the server
func chatWithServer(database *sql.DB, password string, conn net.Conn) {
	fmt.Println("\n💬 Chat mode activated!")
	fmt.Println("Type your messages below. Type 'exit' to return to the main menu.")
	fmt.Println("-------------------------------------------------------------")

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("✉️  Enter message (or type 'exit' to return): ")
		message, _ := reader.ReadString('\n')
		message = strings.TrimSpace(message)

		if message == "exit" {
			fmt.Println("\n🔙 Exiting chat mode... Returning to the main menu.")
			return // Return to menu instead of closing the connection
		}

		// Send message to the client
		_, err := conn.Write([]byte(message))
		if err != nil {
			log.Printf("❌ Failed to send message: %v", err)
			return
		}

		// Save the message to the database as "server" sender
		err = db.SaveEncryptedMessage(database, "server", message,password)
		if err != nil {
			log.Printf("❌ Failed to save server message to database: %v", err)
		}
	}
}

// viewChatLogs retrieves and displays chat logs from the database
func viewChatLogs(database *sql.DB, password string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("\n🔑 Please enter your password to view chat logs: ")
	passwordInput, _ := reader.ReadString('\n')
	passwordInput = strings.TrimSpace(passwordInput)

	if passwordInput == password {
		logs, err := db.GetDecryptedChatLogs(database, password)
		if err != nil {
			log.Printf("❌ Failed to retrieve logs: %v", err)
		} else {
			fmt.Println("\n📜 Chat Logs:")
			fmt.Println("-------------------------------------------------------------")
			if len(logs) == 0 {
				fmt.Println("📭 No logs found.")
			} else {
				for _, log := range logs {
					fmt.Println(log)
				}
			}
			fmt.Println("-------------------------------------------------------------")
		}
	} else {
		fmt.Println("⚠️ Incorrect password. Access denied.")
	}
}

func handleConnection(conn net.Conn, database *sql.DB, encryptionKey string) {
	defer conn.Close()
	log.Printf("✅ Client connected: %s", conn.RemoteAddr())

	// Goroutine to receive messages from the client
	go func() {
		for {
			buffer := make([]byte, 1024)
			n, err := conn.Read(buffer)
			if err != nil {
				log.Printf("❌ Receive message failed: %v", err)
				return
			}
			message := string(buffer[:n])
			log.Printf("📩 Received message: %s", message)

			// Save the client message to the database as "client" sender
			err = db.SaveEncryptedMessage(database, "client", message, encryptionKey)
			if err != nil {
				log.Printf("❌ Failed to save client message to database: %v", err)
			}
		}
	}()

	// Start menu after establishing connection
	startMenu(database, encryptionKey, conn)
}
