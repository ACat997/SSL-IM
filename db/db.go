package db

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/ACat997/SSL-IM/util"
	_ "github.com/mattn/go-sqlite3"
)

// InitDB 初始化并连接到加密的 SQLite 数据库
func InitDB(password string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "file:db/chat.db?cache=shared&mode=rwc")
	if err != nil {
		return nil, err
	}

	// 设置加密密钥
	_, err = db.Exec("PRAGMA key = '" + password + "';")
	if err != nil {
		return nil, err
	}

	// 创建聊天记录表
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS chat_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			message TEXT NOT NULL
		);
	`)
	if err != nil {
		return nil, err
	}

	return db, nil
}

// SaveMessage 保存聊天记录到数据库
func SaveMessage(db *sql.DB, message string) {
	_, err := db.Exec("INSERT INTO chat_logs (message) VALUES (?);", message)
	if err != nil {
		log.Printf("保存聊天记录失败: %v", err)
	}
}

// SaveEncryptedMessage 使用aes加密聊天信息
func SaveEncryptedMessage(db *sql.DB, message, password string) {
	key := util.GenerateKey(password)
	encryptedMessage, err := util.Encrypt(key, message)
	if err != nil {
		log.Printf("加密聊天记录失败: %v", err)
		return
	}
	_, err = db.Exec("INSERT INTO chat_logs (message) VALUES (?);", encryptedMessage)
	if err != nil {
		log.Printf("保存加密聊天记录失败: %v", err)
	}
}

// GetDecryptedChatLogs 解密聊天记录
func GetDecryptedChatLogs(db *sql.DB, password string) ([]string, error) {
	key := util.GenerateKey(password)
	rows, err := db.Query("SELECT message FROM chat_logs;")
	if err != nil {
		return nil, fmt.Errorf("查询聊天记录失败: %v", err)
	}
	defer rows.Close()
	var logs []string
	for rows.Next() {
		var encryptedMessage string
		if err := rows.Scan(&encryptedMessage); err != nil {
			return nil, fmt.Errorf("读取加密聊天记录失败: %v", err)
		}
		plaintext, err := util.Decrypt(key, encryptedMessage)
		if err != nil {
			return nil, fmt.Errorf("解密聊天记录失败: %v", err)
		}
		logs = append(logs, plaintext)
	}
	return logs, nil
}
