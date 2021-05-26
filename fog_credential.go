package api

import (
	"bytes"
	"crypto/x509"
	"errors"
	"time"
)

func checkSelfIssued(cert *x509.Certificate) error {
	if bytes.Compare(cert.RawIssuer, cert.RawSubject) == 0 {
		return errors.New("Unknown Issuer")
	}
	return cert.CheckSignatureFrom(cert)
}

func VerifyChain(certs []*x509.Certificate) (int, error) {
	if len(certs) == 0 {
		return 0, errors.New("Empty Certificates")
	}

	var previous *x509.Certificate
	var count int
	for i, cert := range certs {
		if previous != nil {
			if bytes.Compare(previous.RawIssuer, previous.RawSubject) == 0 {
				return 0, errors.New("Unknown Issuer")
			}
			err := previous.CheckSignatureFrom(cert)
			if err != nil {
				return 0, err
			}
		}

		// If the cert isn't valid (temporally), fail.
		now := time.Now()
		if now.Before(cert.NotBefore) {
			return 0, errors.New("CertNotValidYet")
		}
		if now.After(cert.NotAfter) {
			return 0, errors.New("CertExpired")
		}

		previous = cert
		count = i + 1
	}

	if previous != nil {
		err := checkSelfIssued(previous)
		if err != nil {
			return 0, err
		}
	}
	return count, nil
}

func VerifiedRoot(certs []*x509.Certificate) (*x509.Certificate, error) {
	count, err := VerifyChain(certs)
	if err != nil {
		return nil, err
	}
	return certs[count-1], nil
}
