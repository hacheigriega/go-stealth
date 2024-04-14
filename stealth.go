package stealth

import (
	"bytes"
	"crypto/sha256"
	"hash"

	"github.com/cometbft/cometbft/crypto"
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

// TODO: Combine view and spend keys into one meta address
// st:eth:0x<spendingKey><viewingKey>

func (s StealthSuite) GenerateStealthAddress(viewKey, spendKey []byte) (stealthAddr []byte, ephPubKey crypto.PubKey) {
	ephSK := cmtsecp256k1.GenPrivKey()
	ephPK := ephSK.PubKey()

	// S = V*r, where V is view pubkey and r is ephemeral privkey.
	view_x, view_y := secp256k1.DecompressPubkey(viewKey)
	spend_x, spend_y := secp256k1.DecompressPubkey(spendKey)

	shared_x, shared_y := s.curve.ScalarMult(view_x, view_y, ephSK)

	// Hash the shared secret.
	sBytes := secp256k1.CompressPubkey(shared_x, shared_y)
	hash := s.Hash(sBytes)

	// TODO: View tag

	// Multiply the hashed shared secret with the generator point.
	// stealthPubKey = spendKey + G*hash(S)
	x, y := s.curve.ScalarBaseMult(hash)
	stealthPK_x, stealthPK_y := s.curve.Add(x, y, spend_x, spend_y)

	// Convert the public key to address.
	stealthPK := secp256k1.CompressPubkey(stealthPK_x, stealthPK_y)
	stealthAddr = cmtsecp256k1.PubKey(stealthPK).Address().Bytes()

	// Return the stealth address and the ephemeral public key.
	// TODO: also return view tag.
	return stealthAddr, ephPK
}

func (s StealthSuite) CheckStealthAddress(stealthAddr, ephemeralPK, viewingKey, spendPK []byte) bool {
	// ephemeralPK * viewingKey
	eph_x, eph_y := secp256k1.DecompressPubkey(ephemeralPK)
	shared_x, shared_y := s.curve.ScalarMult(eph_x, eph_y, viewingKey)
	spend_x, spend_y := secp256k1.DecompressPubkey(spendPK)

	// Hash the shared secret.
	sBytes := secp256k1.CompressPubkey(shared_x, shared_y)
	hash := s.Hash(sBytes)

	// TODO: View tag check

	x, y := s.curve.ScalarBaseMult(hash)
	stealthPK_x, stealthPK_y := s.curve.Add(x, y, spend_x, spend_y)
	stealthPK := secp256k1.CompressPubkey(stealthPK_x, stealthPK_y)
	derivedStealthAddr := cmtsecp256k1.PubKey(stealthPK).Address().Bytes()

	return bytes.Equal(derivedStealthAddr, stealthAddr)
}

func (s StealthSuite) ComputeStealthKey(stealthAddr, ephemeralPK, viewingKey, spendKey []byte) []byte {
	// ephemeralPK * viewingKey
	eph_x, eph_y := secp256k1.DecompressPubkey(ephemeralPK)
	shared_x, shared_y := s.curve.ScalarMult(eph_x, eph_y, viewingKey)

	// Hash the shared secret.
	sBytes := secp256k1.CompressPubkey(shared_x, shared_y)
	hash := s.Hash(sBytes)

	// Stealth private key is spendKey + hash
	aScalar, bScalar := new(scalar.ModNScalar), new(scalar.ModNScalar)
	aScalar.SetByteSlice(spendKey)
	bScalar.SetByteSlice(hash)

	result := aScalar.Add(bScalar).Bytes()
	return result[:]
}
