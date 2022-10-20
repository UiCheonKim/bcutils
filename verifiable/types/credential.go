package types

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/btcsuite/btcd/btcec"
	"time"
)

type Credential struct {
	Context           string                 `json:"@context"`
	Id                string                 `json:"id"`
	Type              []string               `json:"type"`
	Issuer            string                 `json:"issuer"`
	IssuanceDate      time.Time              `json:"issuanceDate"`
	ExpirationDate    time.Time              `json:"expirationDate"`
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
	Proof             *Proof                 `json:"proof"`
}

type Proof struct {
	Type               string    `json:"type"`
	Created            time.Time `json:"created"`
	ProofPurpose       string    `json:"proofPurpose"`
	VerificationMethod string    `json:"verificationMethod"`
	Jws                string    `json:"jws"`
}

const credentialId = "https://itsme.id/credentials/"

func generateBaseVc() *Credential {
	cred := &Credential{
		Context:        VcContext,
		Type:           []string{VcType},
		IssuanceDate:   time.Now(),
		ExpirationDate: time.Now(),
	}

	return cred
}

func newVcProof(privateKey *btcec.PrivateKey, data []byte) (*Proof, error) {
	hashed := sha256.Sum256(data)
	sig, err := privateKey.Sign(hashed[:])
	if err != nil {
		return nil, err
	}
	proof := &Proof{
		Type:               "Secp256k1Signature",
		Created:            time.Now(),
		ProofPurpose:       "assertionMethod",
		VerificationMethod: "Digtitalzone DID",
		Jws:                base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sig.Serialize()),
	}

	return proof, nil
}

func NewVcWithSingleValue(issuerPrivateKey *btcec.PrivateKey, ownerDID string, credType string, keyName string, value interface{}) (*Credential, error) {
	vc := generateBaseVc()
	vc.Id = ""
	vc.Type = append(vc.Type, credType)
	vc.Issuer = "Digtitalzone DID"

	cred := make(map[string]interface{})
	cred["id"] = ownerDID
	cred[keyName] = value

	vc.CredentialSubject = cred

	data, err := json.Marshal(vc)
	if err != nil {
		return nil, err
	}

	proof, err := newVcProof(issuerPrivateKey, data)
	if err != nil {
		return nil, err
	}

	vc.Proof = proof

	return vc, nil
}
