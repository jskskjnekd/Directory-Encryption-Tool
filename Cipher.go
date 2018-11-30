package main

type Cipher interface {
	generate()
	getPublicKeyAlgorithm() string
	getPublicKeyData() string
	getPrivateKeyData() string
}
