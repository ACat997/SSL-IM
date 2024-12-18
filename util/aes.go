package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

// GenerateKey 根据用户提供的口令生成 AES 密钥
func GenerateKey(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

// Encrypt 使用 AES-GCM 加密数据
func Encrypt(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("创建 AES Cipher 失败: %v", err)
	}
	nonce := make([]byte, 12) // AES-GCM 的 nonce 长度为 12 字节
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("生成随机数失败: %v", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("创建 AES-GCM 失败: %v", err)
	}
	ciphertext := aesGCM.Seal(nil, nonce, []byte(plaintext), nil)
	result := append(nonce, ciphertext...) // 前 12 字节为 nonce，后续为密文
	return base64.StdEncoding.EncodeToString(result), nil
}

func Decrypt(key []byte, encrypted string) (string, error) {
	// 确保密钥长度为 16、24 或 32 字节
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", fmt.Errorf("invalid key length: must be 16, 24, or 32 bytes, got %d bytes", len(key))
	}

	// Base64 解码
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %v", err)
	}

	// 提取 nonce 和密文
	if len(data) < 12 {
		return "", fmt.Errorf("invalid ciphertext: too short")
	}
	nonce := data[:12]
	ciphertext := data[12:]

	// 创建 AES Cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// 创建 AES-GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create AES-GCM: %v", err)
	}

	// 解密
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %v", err)
	}

	return string(plaintext), nil
}

