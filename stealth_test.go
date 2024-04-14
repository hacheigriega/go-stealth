package stealth

import (
	"fmt"
	"testing"

	cmtsecp256k1 "github.com/cometbft/cometbft/crypto/secp256k1"
)

func TestGenerateStealthAddress(t *testing.T) {
	viewKey := cmtsecp256k1.GenPrivKey()
	spendKey := cmtsecp256k1.GenPrivKey()

	suite := NewStealthSuite()
	stealthAddr, ephPK := suite.GenerateStealthAddress(viewKey.PubKey().Bytes(), spendKey.PubKey().Bytes())

	fmt.Println(stealthAddr)
	fmt.Println(ephPK)

	res := suite.CheckStealthAddress(stealthAddr, ephPK.Bytes(), viewKey, spendKey.PubKey().Bytes())
	fmt.Println(res)

	// Test negative case
	viewKey2 := cmtsecp256k1.GenPrivKey()
	res = suite.CheckStealthAddress(stealthAddr, ephPK.Bytes(), viewKey2, spendKey.PubKey().Bytes())
	fmt.Println(res)

	// Compute stealth key and check if it corresponds to the stealth address.
	stealthKey := suite.ComputeStealthKey(stealthAddr, ephPK.Bytes(), viewKey, spendKey)
	fmt.Println(stealthKey)
}
