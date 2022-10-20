package types

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/btcsuite/btcd/btcec"
	"time"
)

type Presentation struct {
	Context              string       `json:"@context"`
	Id                   string       `json:"id"`
	Type                 []string     `json:"type"`
	VerifiableCredential []Credential `json:"verifiableCredential"`
	Proof                *Proof       `json:"proof"`
}

func generateBaseVP() *Presentation {
	vp := &Presentation{
		Context: VcContext,
		Type:    []string{VpType},
	}

	return vp
}

func newVpProof(privateKey *btcec.PrivateKey, data []byte) (*Proof, error) {
	hashed := sha256.Sum256(data)
	sig, err := privateKey.Sign(hashed[:])
	if err != nil {
		return nil, err
	}
	proof := &Proof{
		Type:               "Secp256k1Signature",
		Created:            time.Now(),
		ProofPurpose:       "assertionMethod",
		VerificationMethod: "Digitalzone DID",
		Jws:                base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sig.Serialize()),
	}

	return proof, nil
}

func NewPresentation(ownerPrivateKey *btcec.PrivateKey, ownerDID string, vcs []Credential) (*Presentation, error) {
	vp := generateBaseVP()

	vp.Id = ownerDID
	vp.VerifiableCredential = vcs

	data, err := json.Marshal(vp)
	if err != nil {
		return nil, err
	}

	proof, err := newVpProof(ownerPrivateKey, data)
	if err != nil {
		return nil, err
	}

	vp.Proof = proof

	return vp, nil

}
