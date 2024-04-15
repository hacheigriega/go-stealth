package stealth

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	cmtsecp256k1 "github.com/cometbft/cometbft/crypto/secp256k1"
)

func TestGenerateStealthAddress(t *testing.T) {
	suite := NewStealthSuite()

	viewKey := cmtsecp256k1.GenPrivKey()
	spendKey := cmtsecp256k1.GenPrivKey()
	metaAddr := MetaAddress(append(viewKey.PubKey().Bytes(), spendKey.PubKey().Bytes()...))

	stealthAddr, ephPubKey := suite.GenerateStealthAddress(metaAddr)
	fmt.Println(stealthAddr)
	fmt.Println(ephPubKey)

	result := suite.CheckStealthAddress(stealthAddr, ephPubKey, viewKey, spendKey.PubKey().Bytes())
	require.Equal(t, true, result)

	// Test negative case
	viewKey2 := cmtsecp256k1.GenPrivKey()
	result = suite.CheckStealthAddress(stealthAddr, ephPubKey, viewKey2, spendKey.PubKey().Bytes())
	require.Equal(t, false, result)

	// Compute stealth key and check if it corresponds to the stealth address.
	stealthKey := suite.ComputeStealthKey(stealthAddr, ephPubKey, viewKey, spendKey)
	fmt.Println(stealthKey)
}
