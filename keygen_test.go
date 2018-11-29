package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func GenerateECKeyPair() RSACipher {
	var r RSACipher
	r.generate()
	return r
}

func TestSignAndVerifyMessage(t *testing.T) {
	r := GenerateECKeyPair()
	messageFromAlice := []byte("This is a message from Alice")
	messageFromBob := []byte("This is a message from Bob")
	signature := r.Sign(messageFromAlice)
	assert.Equal(t, true, r.VerifySignature(messageFromAlice, signature))
	assert.Equal(t, false, r.VerifySignature(messageFromBob, signature))
}
