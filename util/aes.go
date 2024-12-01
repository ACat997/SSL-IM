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

// Decrypt 使用 AES-GCM 解密数据
func Decrypt(key []byte, encrypted string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("Base64 err: %v", err)
	}
	if len(data) < 12 {
		return "", fmt.Errorf("not enough length")
	}
	nonce, ciphertext := data[:12], data[12:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("创建 AES Cipher 失败: %v", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("创建 AES-GCM 失败: %v", err)
	}
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("AES 解密失败: %v", err)
	}
	return string(plaintext), nil
}
