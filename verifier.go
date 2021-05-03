package api

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
		ConfigIds:  []string{"INTEL-SA-00334"},
	}
	return verifier
}
