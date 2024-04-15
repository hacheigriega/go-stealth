package stealth

const PubKeySize = 33

type MetaAddress [PubKeySize * 2]byte

func ParseMetaAddress(metaAddr MetaAddress) (spendPubKey, viewPubKey []byte) {
	return metaAddr[:PubKeySize], metaAddr[PubKeySize:]
}
