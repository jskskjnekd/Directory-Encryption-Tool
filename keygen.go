package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

type RSACipher struct {
	pubKey  rsa.PublicKey
	privKey rsa.PrivateKey
}

func (cipher *RSACipher) generate() {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cipher.privKey = *privKey
	cipher.pubKey = privKey.PublicKey
}

func (cipher *RSACipher) getPublicKey() interface{} {
	return cipher.privKey.E
}

func (cipher *RSACipher) getPrivateKey() interface{} {
	return cipher.privKey.D
}

func (cipher *RSACipher) Sign(message []byte) []byte {
	hashed := sha256.Sum256(message[:])
	signature, _ := rsa.SignPKCS1v15(rand.Reader, &cipher.privKey, crypto.SHA256, hashed[:])
	return signature
}

func (cipher *RSACipher) VerifySignature(message []byte, signature []byte) bool {
	hashed := sha256.Sum256(message)
	err := rsa.VerifyPKCS1v15(&cipher.pubKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return false
	}
	return true
}

func (cipher *RSACipher) Encrypt(message []byte) []byte {
	label := []byte("orders")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &cipher.pubKey, message, label)
	if err != nil {
		panic(err)
	}
	return ciphertext
}

func (cipher *RSACipher) Decrypt(cipherText []byte) []byte {
	label := []byte("orders")
	plainText, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, &cipher.privKey, cipherText, label)
	return plainText
}
