package main

import (
    "flag"
    "os"
)

type Cmd struct {
    AlgorithmType      string
    Subject            string
    publicKeyFilePath  string
    privateKeyFilePath string
}

func (cmd *Cmd) writePrivateKeyToFile(cipher Cipher) {
    fullPrivateKey := cipher.getPublicKeyAlgorithm() + ";" + cipher.getPrivateKeyData()
    f, _ := os.Create(cmd.privateKeyFilePath)
    _, _ = f.Write([]byte(fullPrivateKey))
}

func (cmd *Cmd) exportPublicKeyToCertificateFile(cipher Cipher) {
    var cert certificate
    cert.generate(cipher, cmd.Subject)
    cert.exportJson()
    cert.exportJsonToFile(cmd.publicKeyFilePath)
}

func (cmd *Cmd) generateRSACipher(cipher Cipher) Cipher {
    var rsa RSACipher
    rsa.generate()
    cipher = &rsa
    return cipher
}

func (cmd *Cmd) generateECCipher(cipher Cipher) Cipher {
    var ec ECCipher
    ec.generate()
    cipher = &ec
    return cipher
}

func (cmd *Cmd) generateCipher() Cipher {
    var cipher Cipher
    if cmd.AlgorithmType == "ec" {
        cipher = cmd.generateECCipher(cipher)
    } else if cmd.AlgorithmType == "rsa" {
        cipher = cmd.generateRSACipher(cipher)
    } else {
        panic("Algorithm Not Specified! You can ONLY pick ec or RSA.")
    }
    return cipher
}

func (cmd *Cmd) setFlagParametersForCmd() {
    flag.StringVar(&cmd.AlgorithmType, "t", "", "Algorithm Type: rsa or ec")
    flag.StringVar(&cmd.Subject, "s", "", "Subject Name")
    flag.StringVar(&cmd.publicKeyFilePath, "pub", "", "Public Key File Path")
    flag.StringVar(&cmd.privateKeyFilePath, "priv", "", "Private Key File Path")
}
