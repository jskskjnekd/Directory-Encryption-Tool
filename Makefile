# Basic GO parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test -v
QUESTION1BINARY=keygen

build:
	$(GOBUILD) -o $(QUESTION1BINARY) -v keygen.go Cipher.go certificate.go ECCipher.go RSACipher.go cmd.go
test:
	$(GOTEST) keygen_test.go keygen.go Cipher.go certificate.go ECCipher.go RSACipher.go cmd.go readKeyfileAndSig.go
clean:
	rm -rf $(QUESTION1BINARY)
