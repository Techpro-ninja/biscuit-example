package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
)


func main() {

	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	_, biscuitToken := generateBiscuit(privateKey)
	attenuatedBiscuit := attenuateBiscuit(privateKey, biscuitToken)
	

	e := validateBiscuit(publicKey, biscuitToken)
	if e != nil {
		log.Println("E1", e.Error())
	}
	e = validateBiscuit(publicKey, attenuatedBiscuit)
	if e != nil {
		log.Println("E2", e.Error())
	}

	revokeBiscuit(attenuatedBiscuit)
	e = validateBiscuit(publicKey, biscuitToken)
	if e != nil {
		log.Println("E3", e.Error())
	}

}

// Generate biscuit token
func generateBiscuit(privateKey ed25519.PrivateKey) (err error, biscuitToken []byte){
	
	builder := biscuit.NewBuilder(privateKey)

	fact1, err := parser.FromStringFact(`user("admin")`)
	if err != nil {
		return err, nil
	}

	err = builder.AddAuthorityFact(fact1)
	if err != nil {
		return err, nil
	}

	b, err := builder.Build()
	if err != nil {
		return err, nil
	}
	biscuitToken, err = b.Serialize()
	if err != nil {
		return err, nil
	}

	return nil, biscuitToken

}

// Validate biscuit token
func validateBiscuit(publicKey ed25519.PublicKey, biscuitToken []byte) (err error) {

	b, err := biscuit.Unmarshal(biscuitToken)
	if err != nil {
		return err
	}

	if os.Getenv("revocationId") == base64.URLEncoding.EncodeToString(b.RevocationIds()[0]){
		return errors.New("Token already revoked")
	}


	// Creating the Authorizer
	
	// Authorizer checks the public key provided
	authorizer, err := b.Authorizer(publicKey)
	if err != nil {
		return err
	}

	// Bring in authorizer facts from any source.
	// In our case, we are hard coding it
	fact1, err := parser.FromStringFact(`user("admin")`)
	if err != nil {
		return err
	}

	// In our case, we are hard coding it
	fact2, err := parser.FromStringFact(`operation("create")`)
	if err != nil {
		return err
	}


	authorizer.AddFact(fact1)
	authorizer.AddFact(fact2)
	authorizer.AddPolicy(biscuit.DefaultAllowPolicy)

		

	if err := authorizer.Authorize(); err != nil {
		return err
	} 

	return nil
}

// Attenuate a biscuit token
func attenuateBiscuit(privateKey ed25519.PrivateKey, biscuitToken []byte) (attenuatedBiscuitToken []byte){

	b, err := biscuit.Unmarshal(biscuitToken)
	if err != nil {
		log.Println(err)
		return nil
	}

	check1, err := parser.FromStringCheck(`check if operation("create")`)
	if err != nil {
		log.Println(err)
		return nil
	}

	// Attenuate the biscuit by appending a new block to it
	blockBuilder := b.CreateBlock()
	blockBuilder.AddCheck(check1)

	attenuatedToken, err := b.Append(rand.Reader, blockBuilder.Build())
	if err != nil {
		log.Println(err)
		return nil
	}
	serializedAttenuatedToken, err := attenuatedToken.Serialize()
	if err != nil {
		log.Println(err)
		return nil
	}

	return serializedAttenuatedToken
}

// Sealing a token
func sealBiscuit(biscuitToken []byte){
	b, err := biscuit.Unmarshal(biscuitToken)
	if err != nil {
		log.Println(err)
	}

	b.Seal(rand.Reader)
}


// Revoking a token
func revokeBiscuit(biscuitToken []byte){
	b, err := biscuit.Unmarshal(biscuitToken)
	if err != nil {
		panic(fmt.Errorf("failed to deserialize biscuit: %v", err))
	}

	revokationIds := b.RevocationIds()
	os.Setenv("revocationId", base64.URLEncoding.EncodeToString(revokationIds[0]))

}