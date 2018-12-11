# Basic GO parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test -v
QUESTION1BINARY=keygen
QUESTION2BINARY_LOCK=lock
QUESTION2BINARY_UNLOCK=unlock

build:
	$(GOBUILD) -o $(QUESTION1BINARY) -v keygen.go Cipher.go certificate.go ECCipher.go RSACipher.go cmd.go
	$(GOBUILD) -o $(QUESTION2BINARY_LOCK) -v lock.go locker.go RSACipher.go cmd.go ECCipher.go certificate.go Cipher.go
	$(GOBUILD) -o $(QUESTION2BINARY_UNLOCK) -v unlock.go unlocker.go RSACipher.go cmd.go ECCipher.go certificate.go Cipher.go
test:
	$(GOTEST) keygen_test.go keygen.go Cipher.go certificate.go ECCipher.go RSACipher.go cmd.go readKeyfileAndSig.go
	chmod u+x testSetup.sh
	./testSetup.sh
clean:
	rm -rf $(QUESTION1BINARY)
	rm -rf $(QUESTION2BINARY_LOCK)
	rm -rf $(QUESTION2BINARY_UNLOCK)
	rm -rf testData
	rm -rf testDirectory
