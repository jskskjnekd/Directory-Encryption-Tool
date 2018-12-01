package main

import (
	"flag"
	"log"
	"os"
)

type Cmd struct {
	AlgorithmType      string
	Subject            string
	publicKeyFilePath  string
	privateKeyFilePath string
}

func main() {
	logger, cmd, cipher := generateLoggerCmdCipher()
	cmd.exportPublicKeyToCertificateFile(cipher)
	cmd.writePrivateKeyToFile(cipher)
	closeLogger(logger)
}

func generateLoggerCmdCipher() (*log.Logger, *Cmd, Cipher) {
	logger, cmd := readFromCmdInputs()
	logger.Println(cmd)
	cipher := cmd.generateCipher()
	return logger, cmd, cipher
}

func closeLogger(logger *log.Logger) {
	logger.Println("\n...........END...............")
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

func (cmd *Cmd) generateCipher() Cipher {
	var cipher Cipher
	if cmd.AlgorithmType == "ec" {
		cipher = generateECCipher(cipher)
	} else if cmd.AlgorithmType == "rsa" {
		cipher = generateRSACipher(cipher)
	} else {
		panic("Algorithm Not Specified! You can ONLY pick ec or RSA.")
	}
	return cipher
}

func generateRSACipher(cipher Cipher) Cipher {
	var rsa RSACipher
	rsa.generate()
	cipher = &rsa
	return cipher
}

func generateECCipher(cipher Cipher) Cipher {
	var ec ECCipher
	ec.generate()
	cipher = &ec
	return cipher
}

func readFromCmdInputs() (*log.Logger, *Cmd) {
	logger := createLogger()
	cmd := &Cmd{}
	setFlagParametersForCmd(cmd)
	flag.Parse()
	return logger, cmd
}

func setFlagParametersForCmd(cmd *Cmd) {
	flag.StringVar(&cmd.AlgorithmType, "t", "", "Algorithm Type: rsa or ec")
	flag.StringVar(&cmd.Subject, "s", "", "Subject Name")
	flag.StringVar(&cmd.publicKeyFilePath, "pub", "", "Public Key File Path")
	flag.StringVar(&cmd.privateKeyFilePath, "priv", "", "Private Key File Path")
}

func createLogger() *log.Logger {
	loggerFile, err := os.OpenFile("text.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	logger := log.New(loggerFile, "Keygen|", log.LstdFlags)
	logger.Println("\n\n\n------------------------Log File Created----------------------")
	return logger
}
