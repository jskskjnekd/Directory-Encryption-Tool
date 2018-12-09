package main

import (
	"flag"
	"log"
	"os"
	"strings"
)

func main() {
	logger, locker := readFromLockInputs()
	//
	// get pubkeypath
	//
	pubKeyPath := locker.publicKeyFilePath
	//
	// validate pubkey subject
	//
	locker.validatePubKeyFileSubject(pubKeyPath)
	//
	// create keyfile in current directory if it doesn't exist
	//
	createNamedfile(locker.directoryPath,"keyfile")
	//
	// generate aes key, encrypt and export to keyfile
	//
	aes := locker.generateAESKey(32)
	cipherAes := locker.encryptedAES(aes)
	locker.exportEncryptedAES(cipherAes)
	//
	// export keyfile signature
	//
	createKeySigFile(locker.directoryPath)
	//
	//
	//
	locker.exportKeyfileSignature()
	//
	// filewalk, getting list of files in directory
	//
	fileList := locker.fileWalkRecursive(locker.directoryPath)
	//
	// encrypt the files in this list.
	//
	for _,file := range fileList {
		locker.encryptFileAndReplace(file,aes)
	}
	//
	//
	//
	closelockLogger(logger)
	//
	//
	//
}
//
// if keyfile exists, do nothing, else create keyfile
//
func createNamedfile(filedir string, name string) {

	var dirPath string
	//
	// - - - - - - append keyfile to path
	//
	tempDirPath := strings.Split(filedir,"/")
	tempDirPath = append(tempDirPath,name)
	dirPath = strings.Join(tempDirPath,"/")

	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		// path/to/whatever does not exist
		//
		//
		outFile, _ := os.Create(dirPath)
		defer outFile.Close()
		_ = outFile.Sync()
		outFile.Close()
	}
}
func createKeySigFile(filepath string) {
	var dirPath string
	//
	// - - - - - - append keyfile to path
	//
	tempDirPath := strings.Split(filepath,"/")
	tempDirPath = append(tempDirPath,"keyfile.sig")
	dirPath = strings.Join(tempDirPath,"/")



	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		// path/to/whatever does not exist
		//
		//
		outFile, _ := os.Create(dirPath)
		defer outFile.Close()
		_ = outFile.Sync()
		outFile.Close()
	} else {
		// path exists
		//
		//
		os.Remove(dirPath)
		outFile, _ := os.Create(dirPath)
		defer outFile.Close()
		_ = outFile.Sync()
		outFile.Close()
	}
}

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
		log.Print("error with lockLogger")
	}
	logger := log.New(loggerFile, "Keygen|", log.LstdFlags)
	logger.Println("\n\n\n------------------------Log File Created----------------------")
	return logger
}


