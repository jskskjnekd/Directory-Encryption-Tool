package main

import (
	"crypto/rand"
	"crypto/rsa"
)

type RSACipher struct {
	pubKey  interface{}
	privKey interface{}
}

func (cipher *RSACipher) generate() {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cipher.privKey = privKey.D
	cipher.pubKey = privKey.E
}

func (cipher *RSACipher) getPublicKey() interface{} {
	return cipher.pubKey
}

func (cipher *RSACipher) getPrivateKey() interface{} {
	return cipher.privKey
}
