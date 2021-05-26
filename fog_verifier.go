package api

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type MrSignerVerifier struct {
	MrSigner   [32]byte
	ProductID  uint16
	MinimumSvn uint16
	ConfigIds  []string
	SwIds      []string
}

func NewMrSignerVerifier(s *Signature) *MrSignerVerifier {
	verifier := &MrSignerVerifier{
		MrSigner:   s.MrSigner(),
		ProductID:  s.ProductID(),
		MinimumSvn: s.Version(),
		ConfigIds:  []string{},
		SwIds:      []string{},
	}
	return verifier
}

func (verifier *MrSignerVerifier) AllowHardeningAdvisories(ids []string) {
	verifier.SwIds = ids
}

// https://github.com/mobilecoinfoundation/mobilecoin/blob/e304f92088d2b4fde45bf4ae079c21353e41a89e/attest/core/src/lib.rs#L70 which feature should be used
type Verifier struct {
	TrustAnchors    []*x509.Certificate
	StatusVerifiers []*MrSignerVerifier
}

func (verifier *Verifier) AddMrSigner(mrSignerVerifier *MrSignerVerifier) {
	verifier.StatusVerifiers = []*MrSignerVerifier{mrSignerVerifier}
}

func NewVerifier() (*Verifier, error) {
	block, _ := pem.Decode(AttestationReportSigningCACert)
	if block == nil {
		return nil, errors.New("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &Verifier{
		TrustAnchors: []*x509.Certificate{cert},
	}, nil
}

func GetFogIngestVerifier() (*Verifier, error) {
	signature, err := ParseSignature()
	if err != nil {
		return nil, err
	}

	mrSignerVerifier := NewMrSignerVerifier(signature)
	mrSignerVerifier.AllowHardeningAdvisories([]string{"INTEL-SA-00334"})

	verifier, err := NewVerifier()
	if err != nil {
		return nil, err
	}
	verifier.AddMrSigner(mrSignerVerifier)
	return verifier, nil
}
