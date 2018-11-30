package main

import (
	"github.com/stretchr/testify/assert"
	"math/rand"
	"os/exec"
	"path/filepath"
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
	cert.generate(&r, "test1")
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
	_ = cipher
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
	signaturefromaliceR, signaturefromaliceS := ec.Sign(messageFromAlice)
	assert.Equal(t, true, ec.VerifySignature(messageFromAlice, signaturefromaliceR, signaturefromaliceS))
	assert.Equal(t, false, ec.VerifySignature(messageFromBob, signaturefromaliceR, signaturefromaliceS))
}

func GenerateECCertificate() *certificate {
	var ec ECCipher
	ec.generate()
	var cert certificate
	cert.generate(&ec, "test2")
	return &cert
}

func TestWriteECCertificate(t *testing.T) {
	cert := GenerateECCertificate()
	CertificateWriteToJson(cert)
}

func TestGenAndExecKeygen(t *testing.T) {
	extractBinaryFile()
	publicKeyFileName := "rsapub"
	privateKeyFileName := "rsapriv"
	savePrivateAndPublicFiles(publicKeyFileName, privateKeyFileName, "rsa", t)
	publicKeyFileName = "ecpub"
	privateKeyFileName = "ecpriv"
	savePrivateAndPublicFiles(publicKeyFileName, privateKeyFileName, "ec", t)
}

func savePrivateAndPublicFiles(publicKeyFileName, privateKeyFileName, algorithmType string, t *testing.T) {
	publicKeyFilePath, privateKeyFilePath := runKeygen(publicKeyFileName, privateKeyFileName, algorithmType)
	matchesPubKey, _ := filepath.Glob(publicKeyFilePath)
	matchesPrivKey, _ := filepath.Glob(privateKeyFilePath)
	assert.Equal(t, 1, len(matchesPubKey))
	assert.Equal(t, 1, len(matchesPrivKey))
}

func runKeygen(publicKeyFileName, privateKeyFileName, algorithmType string) (string, string) {
	targetDir := "testData/"
	publicKeyFilePath := targetDir + publicKeyFileName
	privateKeyFilePath := targetDir + privateKeyFileName
	subjectName := "cryptoKitty"
	cmdKeygenReadInputs := exec.Command("./keygen", "-t", algorithmType, "-s", subjectName, "-pub", publicKeyFilePath, "-priv", privateKeyFilePath)
	_ = cmdKeygenReadInputs.Run()
	return publicKeyFilePath, privateKeyFilePath
}

func extractBinaryFile() {
	cmdGenerationKeygen := exec.Command("go", "build", "keygen.go", "Cipher.go", "certificate.go", "ECCipher.go", "RSACipher.go")
	_ = cmdGenerationKeygen.Run()
}
