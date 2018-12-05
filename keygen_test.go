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

func generateAESKeyForTestONLY(length int) []byte {
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
	AesKey := generateAESKeyForTestONLY(AesKeyLength)
	r := GenerateRSACipher()
	cipherText := r.Encrypt(AesKey)
	decryptedMessage := r.Decrypt(cipherText)
	assert.Equal(t, AesKey, decryptedMessage)
}

func GenerateRSACertificate() (*certificate, RSACipher) {
	var cert certificate
	r := GenerateRSACipher()
	cert.generate(&r, "test2")
	return &cert, r
}

func TestWriteCertificate(t *testing.T) {
	cert, _ := GenerateRSACertificate()
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

func TestReadRSAPublicKeyOnly(t *testing.T) {
	var r RSACipher
	filePath := "testData/unitTestRSApub"
	r.getPublicKeyFromFile(filePath)
	assert.Equal(t, "256;26023832331713257274664441664392187466883042725358585720275956730147956071181952518736788753503245520018091472431298471955798654448589301155934277931240162176328640252080569832771810664621758643489083345172598021914700888333945962112020851927565219587419183397467185855105332892445955229511444317887564060487953991049237007601889670798204318122430929398590483512206219845564225686018203864750776335912499703496111958149689443194133537519829620331821610185016897280252409712240022577021507003468215361037772942784978964592190540530127987606419086408365472755528016251641560385132904849997624687825983210867659768250627;65537", r.getPublicKeyData())
}

func TestReadRSAPrivateKeyAndPublicKey(t *testing.T) {
	var r RSACipher
	filePath := "testData/unitTestRSApriv"
	r.getPrivateKeyFromFile(filePath)
	assert.Equal(t, "256;26023832331713257274664441664392187466883042725358585720275956730147956071181952518736788753503245520018091472431298471955798654448589301155934277931240162176328640252080569832771810664621758643489083345172598021914700888333945962112020851927565219587419183397467185855105332892445955229511444317887564060487953991049237007601889670798204318122430929398590483512206219845564225686018203864750776335912499703496111958149689443194133537519829620331821610185016897280252409712240022577021507003468215361037772942784978964592190540530127987606419086408365472755528016251641560385132904849997624687825983210867659768250627;65537;14628652259034078428958268320432857565649500190765678897950260859341298833671714158265762816104789126103826690943574403876460967543311867412066753116360034401573875930949664962377183955394137486093929084885766988530716705467485073228967578391008173849894299653061493917971229439213100853795590409554570090000523561267790915989895373370071171598212999383578634022107493959143360641003367894021562188018495271161422353318844927673352753237248986940336861460781245491176541321183824390259185249058423509952784064018544210169078407330554311000895232357211784690999626443333272079187320635216987495891116164028211752211073", r.getPrivateKeyData())
}

func TestReadECPublicKeyOnly(t *testing.T) {
	var ec ECCipher
	filePath := "testData/unitTestECpub"
	ec.getPublicKeyFromFile(filePath)
	assert.Equal(t, "42959308427456482066000506741001434821838233333725386843040209036964842026452;58455881548121703908827263112628762219990967672922710811232574208307069287946", ec.getPublicKeyData())
}

func TestReadECPrivateKeyAndPublicKey(t *testing.T) {
	var ec ECCipher
	filePath := "testData/unitTestECpriv"
	ec.getPrivateKeyFromFile(filePath)
	assert.Equal(t, "42959308427456482066000506741001434821838233333725386843040209036964842026452;58455881548121703908827263112628762219990967672922710811232574208307069287946", ec.getPublicKeyData())
}
