package main

import (
	"fmt"
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

func TestRSAEncryptionAndDecryption(t *testing.T) {
	AesKeyLength := 32
	AesKey := generateAESKey(AesKeyLength)
	r := GenerateRSACipher()
	cipherText := r.Encrypt(AesKey)
	decryptedMessage := r.Decrypt(cipherText)
	assert.Equal(t, AesKey, decryptedMessage)
}

func GenerateRSACertificate() *certificate {
	var cert certificate
	r := GenerateRSACipher()
	cert.generate(&r)
	return &cert
}

func TestWriteCertificate(t *testing.T) {
	cert := GenerateRSACertificate()
	CertificateWriteToJson(cert)
}

func CertificateWriteToJson(cert *certificate) {
	cert.exportJson()
	certificateFilePath := "testData/"
	certificateFileName := "myX509Certificate"
	cert.exportJsonToFile(certificateFilePath + certificateFileName)
}

func TestCipherGeneration(t *testing.T) {
	var cipher Cipher
	r := GenerateRSACipher()
	cipher = &r
	fmt.Println(cipher)
}

func TestECGeneration(t *testing.T) {
	var ec ECCipher
	ec.generate()
}

func TestECSignAndVerify(t *testing.T) {
	var ec ECCipher
	ec.generate()
	messageFromAlice := []byte("This is a message from Alice")
	messageFromBob := []byte("This is a message from Bob")
	signatureFromAlice_r, signatureFromAlice_s := ec.Sign(messageFromAlice)
	assert.Equal(t, true, ec.VerifySignature(messageFromAlice, signatureFromAlice_r, signatureFromAlice_s))
	assert.Equal(t, false, ec.VerifySignature(messageFromBob, signatureFromAlice_r, signatureFromAlice_s))
}

func GenerateECCertificate() *certificate {
	var ec ECCipher
	ec.generate()
	var cert certificate
	cert.generate(&ec)
	return &cert
}

func TestWriteECCertificate(t *testing.T) {
	cert := GenerateECCertificate()
	CertificateWriteToJson(cert)
}
