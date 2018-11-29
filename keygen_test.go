package main

import (
	"fmt"
	"testing"
)

func GenerateECKeyPair() RSACipher {
	var r RSACipher
	r.generate()
	return r
}

func TestSignAndVerifyMessage(t *testing.T) {
	r := GenerateECKeyPair()
	fmt.Println(r)
}
