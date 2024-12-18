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
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        sender TEXT NOT NULL,                 -- 消息发送方（server 或 client）
        message TEXT NOT NULL                 -- 消息内容（加密后的）
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
		log.Printf("save message err: %v", err)
	}
}

// SaveEncryptedMessage 使用aes加密聊天信息
func SaveEncryptedMessage(db *sql.DB, sender string, message string, encryptionKey string) error {
	key := util.GenerateKey(encryptionKey)
	encryptedMessage, err := util.Encrypt(key, message)
	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}
	_, err = db.Exec("INSERT INTO messages (sender, message) VALUES (?, ?)", sender, encryptedMessage)
	if err != nil {
		return fmt.Errorf("database insert failed: %v", err)
	}
	return nil
}

// GetDecryptedChatLogs 解密聊天记录
func GetDecryptedChatLogs(db *sql.DB, password string) ([]string, error) {
	// 生成解密密钥
	key := util.GenerateKey(password)

	// 查询消息记录，包含 sender 和 message
	rows, err := db.Query("SELECT sender, message FROM messages;")
	if err != nil {
		return nil, fmt.Errorf("failed to query messages: %v", err)
	}
	defer rows.Close()

	var logs []string
	for rows.Next() {
		var sender, encryptedMessage string

		// 读取数据库中 sender 和 message 字段
		if err := rows.Scan(&sender, &encryptedMessage); err != nil {
			return nil, fmt.Errorf("failed to read message: %v", err)
		}

		// 解密消息内容
		plaintext, err := util.Decrypt(key, encryptedMessage)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt message: %v", err)
		}

		// 将 sender 和解密后的消息拼接成可读的日志格式
		logs = append(logs, fmt.Sprintf("[%s] %s", sender, plaintext))
	}

	return logs, nil
}
