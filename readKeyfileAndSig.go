package main

import (
	"io/ioutil"
	"math/big"
	"strings"
)

func readKeyfileAndSignature(directoryPath, pubKeyfilePath string) bool {
	keyfilePath := directoryPath + "keyfile"
	keyfileSigPath := directoryPath + "keyfile.sig"
	signature, _ := ioutil.ReadFile(keyfileSigPath)
	ele := strings.Split(string(signature), ";")
	r := new(big.Int)
	s := new(big.Int)
	_, _ = r.SetString(ele[0], 10)
	_, _ = s.SetString(ele[1], 10)
	var ec_fromPub ECCipher
	ec_fromPub.getPublicKeyFromFile(pubKeyfilePath)
	message, _ := ioutil.ReadFile(keyfilePath)
	return ec_fromPub.VerifySignature(message, r, s)
}
