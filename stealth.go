package stealth

import (
	"bytes"
	"crypto/sha256"
	"hash"

	cmtsecp256k1 "github.com/cometbft/cometbft/crypto/secp256k1"
	scalar "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type StealthSuite struct {
	curve  *secp256k1.BitCurve
	hasher hash.Hash
}

// NewStealthSuite creates a new Stealth Suite object with secp256k1 curve
// and SHA256 hasher.
func NewStealthSuite() StealthSuite {
	return StealthSuite{
		curve:  secp256k1.S256(),
		hasher: sha256.New(),
	}
}

func (s StealthSuite) Hash(hashInput []byte) []byte {
	s.hasher.Write(hashInput)
	hashString := s.hasher.Sum(nil)
	s.hasher.Reset()
	return hashString
}

func (s StealthSuite) GenerateStealthAddress(metaAddr MetaAddress) (stealthAddr, ephPubKey []byte) {
	viewPubKey, spendPubKey := ParseMetaAddress(metaAddr)
	ephPrivKey := cmtsecp256k1.GenPrivKey()

	// S = V*r, where V is view public key and r is ephemeral private key.
	view_x, view_y := secp256k1.DecompressPubkey(viewPubKey)
	shared_x, shared_y := s.curve.ScalarMult(view_x, view_y, ephPrivKey)

	// Hash the shared secret.
	sBytes := secp256k1.CompressPubkey(shared_x, shared_y)
	hash := s.Hash(sBytes)

	// TODO: View tag

	// stealthPubKey = spendPubKey + G*hash(S)
	x, y := s.curve.ScalarBaseMult(hash)
	spend_x, spend_y := secp256k1.DecompressPubkey(spendPubKey)
	stealth_x, stealth_y := s.curve.Add(x, y, spend_x, spend_y)

	// Convert the public key to address.
	stealthPubKey := secp256k1.CompressPubkey(stealth_x, stealth_y)
	stealthAddr = cmtsecp256k1.PubKey(stealthPubKey).Address().Bytes()

	// Return the stealth address and the ephemeral public key.
	// TODO: also return view tag.
	return stealthAddr, ephPrivKey.PubKey().Bytes()
}

func (s StealthSuite) CheckStealthAddress(stealthAddr, ephPubKey, viewPrivKey, spendPubKey []byte) bool {
	// S = v*R, where v is view private key and R is ephemeral public key.
	eph_x, eph_y := secp256k1.DecompressPubkey(ephPubKey)
	shared_x, shared_y := s.curve.ScalarMult(eph_x, eph_y, viewPrivKey)

	// Hash the shared secret.
	sBytes := secp256k1.CompressPubkey(shared_x, shared_y)
	hash := s.Hash(sBytes)

	// TODO: View tag check

	// stealthPubKey = spendPubKey + G*hash(S)
	x, y := s.curve.ScalarBaseMult(hash)
	spend_x, spend_y := secp256k1.DecompressPubkey(spendPubKey)
	stealth_x, stealth_y := s.curve.Add(x, y, spend_x, spend_y)

	stealthPubKey := secp256k1.CompressPubkey(stealth_x, stealth_y)
	derivedStealthAddr := cmtsecp256k1.PubKey(stealthPubKey).Address().Bytes()
	return bytes.Equal(derivedStealthAddr, stealthAddr)
}

func (s StealthSuite) ComputeStealthKey(stealthAddr, ephPubKey, viewPrivKey, spendPrivKey []byte) []byte {
	// S = v*R, where v is view private key and R is ephemeral public key.
	eph_x, eph_y := secp256k1.DecompressPubkey(ephPubKey)
	shared_x, shared_y := s.curve.ScalarMult(eph_x, eph_y, viewPrivKey)

	// Hash the shared secret.
	sBytes := secp256k1.CompressPubkey(shared_x, shared_y)
	hash := s.Hash(sBytes)

	// stealthPrivKey = spendPrivKey + hash(S)
	aScalar, bScalar := new(scalar.ModNScalar), new(scalar.ModNScalar)
	aScalar.SetByteSlice(spendPrivKey)
	bScalar.SetByteSlice(hash)
	result := aScalar.Add(bScalar).Bytes()
	return result[:]
}
