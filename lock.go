package main

import (
	"fmt"
	"flag"
	"log"
	"math/rand"
	"os"
)

func main() {
	logger, locker := readFromLockInputs()
	//	locker.exportPublicKeyToCertificateFile(cipher)
	//	writePrivateKeyToFile(cipher, )
	closelockLogger(logger)
	locker.generateCipher("ec")
	locker.generateCipher("rsa")

	result := locker.getPubKeyJSONMap()

	fmt.Println(result["users"])

}

func generateAESKey(length int) []byte {
	Aes_key := make([]byte, length)
	_, _ = rand.Read(Aes_key)
	return Aes_key
}

//func generateLogLockerCipher() (*log.Logger, *Locker, Cipher) {
//	logger, locker := readFromLockInputs()
//	logger.Println(locker)
//	cipher := locker.generateCipher()
//	return logger, locker
//}

func readFromLockInputs() ( *log.Logger, *Locker) {
	logger := createlockLogger()
	l := &Locker{}
	l.setFlagParameters()
	flag.Parse()
	return logger, l
}

func closelockLogger(logger *log.Logger) {
	logger.Println("\n...........END...............")
}


func createlockLogger() *log.Logger {
	loggerFile, err := os.OpenFile("text.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	logger := log.New(loggerFile, "Keygen|", log.LstdFlags)
	logger.Println("\n\n\n------------------------Log File Created----------------------")
	return logger
}


