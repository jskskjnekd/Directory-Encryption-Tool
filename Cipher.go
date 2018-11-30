package main

type Cipher interface {
	generate()
	getPublicKeyAlgorithm() string
	getPublicKeyData() string
	getPrivateKey() interface{}
	Sign(message []byte) []byte
	VerifySignature(message []byte, signature []byte) bool
	Encrypt(message []byte) []byte
	Decrypt(cipherText []byte) []byte
}
