package api

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/jadeydi/mobilecoin-account/block"
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

// https://github.com/mobilecoinfoundation/mobilecoin/blob/e304f92088d2b4fde45bf4ae079c21353e41a89e/attest/core/src/lib.rs#L70
// which feature should be used
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

type IasReportVerifier struct {
	TrustAnchors []*x509.Certificate
	//ORVerifiers  []byte
	//AndVerifiers []byte
}

type VerificationReportData struct {
	ID        string
	Timestamp string
	Version   float64
}

// https://github.com/mobilecoinfoundation/mobilecoin/blob/6abc426b2ad7a1d91e06c7ddab774f4055fb9df9/attest/core/src/ias/verifier.rs#L385
// verify
func (verifier *IasReportVerifier) Verify(report *block.VerificationReport) (*VerificationReportData, error) {
	if len(report.Chain) == 0 {
		return nil, errors.New("No Chain Error")
	}

	hash := sha256.Sum256([]byte(report.HttpBody))

	var parsedChains []*x509.Certificate
	for _, chain := range report.Chain {
		cert, err := x509.ParseCertificate(chain)
		if err != nil {
			return nil, err
		}
		parsedChains = append(parsedChains, cert)
	}
	// First, find any certs for the signer pubkey
	var filteredChains []*x509.Certificate
	for _, cert := range parsedChains {
		switch cert.PublicKey.(type) {
		case *rsa.PublicKey:
			pub := cert.PublicKey.(*rsa.PublicKey)
			err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], report.GetSig().GetContents())
			if err == nil {
				filteredChains = append(filteredChains, cert)
			}
		}
	}

	// Then construct a set of chains, one for each signer certificate
	var signerChains [][]*x509.Certificate
	for _, cert := range filteredChains {
		signerChain := []*x509.Certificate{cert}
	OUTER:
		for {
			// MAX_CHAIN_DEPTH = 5
			if len(signerChain) > 5 {
				signerChain = []*x509.Certificate{}
				break
			}

			for _, cacert := range parsedChains {
				existingCert := signerChain[len(signerChain)-1]
				pub := existingCert.PublicKey.(*rsa.PublicKey)
				if !pub.Equal(cacert.PublicKey) {
					ca := *cacert
					signerChain = append(signerChain, &ca)
					goto OUTER
				}
			}
			break
		}
		if len(signerChain) > 0 {
			signerChains = append(signerChains, signerChain)
		}
	}
	return nil, nil
}

// https://github.com/mobilecoinfoundation/mobilecoin/blob/6abc426b2ad7a1d91e06c7ddab774f4055fb9df9/attest/core/src/ias/verify.rs#L261
// TryFrom
func TryFromVerificationReport(*VerificationReportData, error) {
}
