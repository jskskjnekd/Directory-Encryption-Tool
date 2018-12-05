package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
)

type ECCipher struct {
	EllipticCurve elliptic.Curve
	privateKey    *ecdsa.PrivateKey
	publicKey     *ecdsa.PublicKey
}

func (ec *ECCipher) generate() {
	ec.EllipticCurve = elliptic.P256()
	ec.privateKey, _ = ecdsa.GenerateKey(ec.EllipticCurve, rand.Reader)
	ec.publicKey = &ec.privateKey.PublicKey
}

func (ec *ECCipher) getPublicKeyAlgorithm() string {
	return "ECC P256"
}

func (ec *ECCipher) getPublicKeyData() string {
	return ec.publicKey.X.String() + ";" + ec.publicKey.Y.String()
}

func (ec *ECCipher) getPrivateKeyData() string {
	return ec.privateKey.D.String()
}

func (ec *ECCipher) Sign(message []byte) (r, s *big.Int) {
	r, s, _ = ecdsa.Sign(rand.Reader, ec.privateKey, message)
	return r, s
}

func (ec *ECCipher) VerifySignature(message []byte, r, s *big.Int) bool {
	return ecdsa.Verify(ec.publicKey, message, r, s)
}

func (ec *ECCipher) getPublicKeyFromFile(filePath string) {
	var certFromJsonFile certificate
	jsonFile, _ := os.Open(filePath)
	jsonContent, _ := ioutil.ReadAll(jsonFile)
	_ = json.Unmarshal(jsonContent, &certFromJsonFile)
	publicKeyEle := strings.Split(certFromJsonFile.PublicKeyData, ";")
	ec.EllipticCurve = elliptic.P256()
	X := new(big.Int)
	Y := new(big.Int)
	_, _ = X.SetString(publicKeyEle[0], 10)
	_, _ = Y.SetString(publicKeyEle[1], 10)
	ec.publicKey = &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     X,
		Y:     Y,
	}
}

func (ec *ECCipher) getPrivateKeyFromFile(filePath string) {
	privateKeyContent, _ := ioutil.ReadFile(filePath)
	privateKeyEle := strings.Split(string(privateKeyContent), ";")
	if privateKeyEle[0] != "ECC P256" {
		panic("Cipher Type does not match!")
	}
	D := new(big.Int)
	_, _ = D.SetString(privateKeyEle[1], 10)
	ec.EllipticCurve = elliptic.P256()
	D_bytes := D.Bytes()
	//fmt.Println(D_bytes)
	tempX, tempY := ec.EllipticCurve.ScalarBaseMult(D_bytes)
	ec.publicKey = &ecdsa.PublicKey{X: tempX, Y: tempY}
	ec.privateKey = &ecdsa.PrivateKey{ecdsa.PublicKey{X: tempX, Y: tempY}, D}
}
