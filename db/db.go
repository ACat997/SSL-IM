package db

import (
	"database/sql"
	"log"

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
