package main

import (
	"encoding/json"
	"os"
)

type certificate struct {
	Subject            string
	PublicKeyAlgorithm string
	PublicKeyData      string
}

func (cert *certificate) generate(cipher *RSACipher) {
	cert.PublicKeyAlgorithm = cipher.getPublicKeyAlgorithm()
	cert.PublicKeyData = cipher.getPublicKeyData()
	cert.Subject = "CryptoCurrency"
}

func (cert *certificate) exportJson() []byte {
	certificateJson, _ := json.Marshal(*cert)
	return certificateJson
}

func (cert *certificate) exportJsonToFile(filePath string) {
	certificateJson := cert.exportJson()
	jsonFile, _ := os.Create(filePath)
	defer jsonFile.Close()
	_, _ = jsonFile.Write(certificateJson)
	jsonFile.Sync()
	jsonFile.Close()
}
