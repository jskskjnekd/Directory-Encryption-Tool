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

func (cert *certificate) generate(cipher Cipher, subjectName string) {
	cert.PublicKeyAlgorithm = cipher.getPublicKeyAlgorithm()
	cert.PublicKeyData = cipher.getPublicKeyData()
	cert.Subject = subjectName
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
	_ = jsonFile.Sync()
	jsonFile.Close()
}
