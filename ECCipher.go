package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

type ECCipher struct {
	EllipticCurve elliptic.Curve
	privateKey    *ecdsa.PrivateKey
}

func (ec *ECCipher) generate() {
	ec.EllipticCurve = elliptic.P256()
	ec.privateKey, _ = ecdsa.GenerateKey(ec.EllipticCurve, rand.Reader)
}

func (ec *ECCipher) getPublicKeyAlgorithm() string {
	return "ECC P256"
}

func (ec *ECCipher) getPublicKeyData() string {
	return ec.privateKey.PublicKey.X.String() + ";" + ec.privateKey.PublicKey.Y.String()
}

func (ec *ECCipher) Sign(message []byte) (r, s *big.Int) {
	r, s, _ = ecdsa.Sign(rand.Reader, ec.privateKey, message)
	return r, s
}

func (ec *ECCipher) VerifySignature(message []byte, r, s *big.Int) bool {
	return ecdsa.Verify(&ec.privateKey.PublicKey, message, r, s)
}
