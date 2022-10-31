package reverse

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
)

func OpensslEncrypt(keyStr string, ivStr string, text string) (string, error) {

	plaintext := []byte(text)
	key, err := hex.DecodeString(keyStr)
	if err != nil {
		return "", err
	}
	iv, err := hex.DecodeString(ivStr)
	if err != nil {
		return "", err
	}

	plaintext = PKCS7Padding(plaintext)
	ciphertext := make([]byte, len(plaintext))
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)
	return hex.EncodeToString(ciphertext), nil
}

func OpensslDecrypt(keyStr string, ivStr string, text string) (string, error) {

	key, err := hex.DecodeString(keyStr)
	if err != nil {
		return "", err
	}
	iv, err := hex.DecodeString(ivStr)
	if err != nil {
		return "", err
	}
	ciphertext, err := hex.DecodeString(text)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	plaintext = PKCS7UnPadding(plaintext)
	return string(plaintext), nil
}

func MustEncode(key, iv, text string) string {
	s, err := OpensslEncrypt(key, iv, text)
	if err != nil {
		panic(err)
	}
	return s
}

func MustDecode(key, iv, text string) string {
	s, err := OpensslDecrypt(key, iv, text)
	if err != nil {
		panic(err)
	}
	return s
}

func PKCS7Padding(ciphertext []byte) []byte {
	padding := aes.BlockSize - len(ciphertext)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(plaintext []byte) []byte {
	length := len(plaintext)
	unpadding := int(plaintext[length-1])
	return plaintext[:(length - unpadding)]
}
