package api

import (
	"crypto/ed25519"
	"crypto/x509"
	"errors"

	"github.com/ChainSafe/go-schnorrkel"
	"github.com/MixinNetwork/mobilecoin-go/block"
)

const (
	SUPER_CONTEXT = "Fog authority signature"
)

type FullyValidatedFogPubkey struct {
}

type IngestReportVerifier struct {
	Verifier *Verifier
}

type FogResolver struct {
	Responses map[string]*block.ReportResponse
	Verifier  *IngestReportVerifier
}

func verifyAuthority(recipient *block.PublicAddress, certs []*x509.Certificate, sig []byte) (bool, error) {
	cert, err := VerifiedRoot(certs)
	if err != nil {
		return false, err
	}
	/*
		pub, err := x509.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
		if err != nil {
			return err
		}
	*/

	signingCtx := []byte(SUPER_CONTEXT)
	verifyTranscript := schnorrkel.NewSigningContext(signingCtx, cert.RawSubjectPublicKeyInfo)

	view := recipient.ViewPublicKey.GetData()
	var view32 [32]byte
	copy(view32[:], view)
	public := schnorrkel.NewPublicKey(view32)
	var sig64 [64]byte
	copy(sig64[:], sig)
	signature := schnorrkel.Signature{}
	err = signature.Decode(sig64)
	if err != nil {
		return false, err
	}
	return public.Verify(&signature, verifyTranscript), nil
}

func mcPublicKey(cert *x509.Certificate) (ed25519.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, err
	}
	switch pub := pub.(type) {
	case ed25519.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("unknown type of public key")
	}
}

func verifyFogSig(recipient *block.PublicAddress, responses *block.ReportResponse) error {
	var certs []*x509.Certificate
	for _, buf := range responses.GetChain() {
		cert, err := x509.ParseCertificate(buf)
		if err != nil {
			return err
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return errors.New("Empty Chain Error")
	}

	authoritySig := recipient.FogAuthoritySig
	valid, err := verifyAuthority(recipient, certs, authoritySig)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("Verify Authority Error")
	}

	// leaf
	leaf := certs[0]
	public, err := mcPublicKey(leaf)
	if err != nil {
		return err
	}
	_ = public
	return nil
}

func (resolver *FogResolver) GetFogPubkey(recipient *block.PublicAddress) error {
	response := resolver.Responses[recipient.FogReportUrl]

	err := verifyFogSig(recipient, response)
	if err != nil {
		return err
	}
	return nil
}
