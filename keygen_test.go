package main

import (
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

func GenerateRSACipher() RSACipher {
	var r RSACipher
	r.generate()
	return r
}

func generateAESKey(length int) []byte {
	AES_key := make([]byte, length)
	_, _ = rand.Read(AES_key)
	return AES_key
}

func TestSignAndVerifyMessage(t *testing.T) {
	r := GenerateRSACipher()
	messageFromAlice := []byte("This is a message from Alice")
	messageFromBob := []byte("This is a message from Bob")
	signatureFromAlice := r.Sign(messageFromAlice)
	assert.Equal(t, true, r.VerifySignature(messageFromAlice, signatureFromAlice))
	assert.Equal(t, false, r.VerifySignature(messageFromBob, signatureFromAlice))
}

func TestEncryptionAndDecryption(t *testing.T) {
	AesKeyLength := 32
	AesKey := generateAESKey(AesKeyLength)
	r := GenerateRSACipher()
	cipherText := r.Encrypt(AesKey)
	decryptedMessage := r.Decrypt(cipherText)
	assert.Equal(t, AesKey, decryptedMessage)
}

func GenerateCertificate() *certificate {
	var cert certificate
	r := GenerateRSACipher()
	cert.generate(&r)
	return &cert
}

func TestWriteCertificate(t *testing.T) {
	cert := GenerateCertificate()
	cert.exportJson()
	certificateFilePath := "testData/"
	certificateFileName := "myX509Certificate"
	cert.exportJsonToFile(certificateFilePath + certificateFileName)
}
