package api

import (
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/bwesterb/go-ristretto"
	account "github.com/jadeydi/mobilecoin-account"
)

const (
	BULLETPROOF_DOMAIN_TAG               = "mc_bulletproof_transcript"
	AMOUNT_VALUE_DOMAIN_TAG              = "mc_amount_value"
	AMOUNT_BLINDING_DOMAIN_TAG           = "mc_amount_blinding"
	HASH_TO_POINT_DOMAIN_TAG             = "mc_onetime_key_hash_to_point"
	HASH_TO_SCALAR_DOMAIN_TAG            = "mc_onetime_key_hash_to_scalar"
	RING_MLSAG_CHALLENGE_DOMAIN_TAG      = "mc_ring_mlsag_challenge"
	TXOUT_CONFIRMATION_NUMBER_DOMAIN_TAG = "mc_tx_out_confirmation_number"
	MILLIMOB_TO_PICOMOB                  = 1_000_000_000
	PICOMOB                              = 1_000_000_000_000 // precision = 12

	MAX_TOMBSTONE_BLOCKS = 100
	MAX_INPUTS           = 16
	RING_SIZE            = 11 // Each input ring must contain this many elements.
)

type UTXO struct {
	TransactionHash string
	Index           uint32
	Amount          uint64
	PrivateKey      string
	ScriptPubKey    string
}

type InputCredential struct {
	Ring                []*TxOut
	MembershipProofs    []*TxOutMembershipProof
	RealIndex           int
	OnetimePrivateKey   *ristretto.Scalar
	RealOutputPublicKey *ristretto.Point
	ViewPrivateKey      *ristretto.Scalar
}

func NewInputCredential(utxo *UTXO, proofSet map[string]*TxOutMembershipProof, tops []*TxOutWithProof, viewPrivate string) (*InputCredential, error) {
	data, err := hex.DecodeString(utxo.ScriptPubKey)
	if err != nil {
		return nil, err
	}
	var txOut TxOut
	err = json.Unmarshal(data, &txOut)
	if err != nil {
		return nil, err
	}
	proof := proofSet[txOut.PublicKey]

	onetimePrivateKey, err := RecoverOnetimePrivateKey(txOut.PublicKey, utxo.PrivateKey)
	if err != nil {
		return nil, err
	}

	var realIndex int
	for i := range tops {
		if tops[i].TxOut.PublicKey == txOut.PublicKey {
			realIndex = i
			break
		}
	}
	if realIndex == 0 {
		t := &TxOutWithProof{
			TxOut: &txOut,
			Proof: proof,
		}
		if len(tops) == 0 {
			tops = append(tops, t)
		} else {
			tops[0] = t
		}
	}

	sort.Slice(tops, func(i, j int) bool {
		return tops[i].TxOut.PublicKey < tops[j].TxOut.PublicKey
	})

	for i := range tops {
		if tops[i].TxOut.PublicKey == txOut.PublicKey {
			realIndex = i
			break
		}
	}

	realOutputPublicKey := hexToPoint(txOut.PublicKey)
	ring := make([]*TxOut, len(tops))
	proofs := make([]*TxOutMembershipProof, len(tops))
	for i := range tops {
		ring[i] = tops[i].TxOut
		proofs[i] = tops[i].Proof
	}

	return &InputCredential{
		Ring:                ring,
		MembershipProofs:    proofs,
		RealIndex:           realIndex,
		OnetimePrivateKey:   onetimePrivateKey,
		ViewPrivateKey:      account.ViewPrivateKeyFromHex(viewPrivate),
		RealOutputPublicKey: realOutputPublicKey,
	}, nil
}

type OutputAndSharedSecret struct {
	Output       *TxOut           `json:"tx_out"`
	SharedSecret *ristretto.Point `json:"shared_secret"`
	Index        int
	Value        uint64
	Receiver     *account.PublicAddress
	PubkeyExpiry uint64
}

func (o *OutputAndSharedSecret) GetValueWithBlinding() (uint64, *ristretto.Scalar) {
	mask := GetValueMask(o.SharedSecret)
	maskedValue := uint64(o.Output.Amount.MaskedValue)
	value := maskedValue ^ mask

	blinding := GetBlinding(o.SharedSecret)
	return value, blinding
}

type TransactionBuilder struct {
	InputCredentials        []*InputCredential       `json:"input_credentials"`
	OutputsAndSharedSecrets []*OutputAndSharedSecret `json:"outputs_and_shared_secrets"`
	TombstoneBlock          uint64                   `json:"tombstone_block"`
	Fee                     uint64                   `json:"fee"`
}

func (tb *TransactionBuilder) Build() (*Tx, error) {
	sort.Slice(tb.InputCredentials, func(i, j int) bool {
		return tb.InputCredentials[i].Ring[0].PublicKey < tb.InputCredentials[j].Ring[0].PublicKey
	})

	inputList := make([]*TxIn, len(tb.InputCredentials))
	for i := range tb.InputCredentials {
		inputList[i] = &TxIn{
			Ring:   tb.InputCredentials[i].Ring,
			Proofs: tb.InputCredentials[i].MembershipProofs,
		}
	}

	sort.Slice(tb.OutputsAndSharedSecrets, func(i, j int) bool {
		return tb.OutputsAndSharedSecrets[i].Output.PublicKey < tb.OutputsAndSharedSecrets[j].Output.PublicKey
	})

	tombstoneBlock := tb.TombstoneBlock

	outputList := make([]*TxOut, len(tb.OutputsAndSharedSecrets))
	for i := range tb.OutputsAndSharedSecrets {
		outputList[i] = tb.OutputsAndSharedSecrets[i].Output

		if tombstoneBlock > tb.OutputsAndSharedSecrets[i].PubkeyExpiry {
			tombstoneBlock = tb.OutputsAndSharedSecrets[i].PubkeyExpiry
		}
	}

	txPrefix := &TxPrefix{
		Inputs:         inputList,
		Outputs:        outputList,
		Fee:            FeeValue(tb.Fee),
		TombstoneBlock: TombstoneValue(tombstoneBlock),
	}

	message := HashOfTxPrefix(txPrefix)
	signatures, err := SignRctBulletproofs(message, tb.InputCredentials, tb.Fee, tb.OutputsAndSharedSecrets)
	if err != nil {
		return nil, err
	}

	return &Tx{
		Prefix:    txPrefix,
		Signature: signatures,
	}, nil
}
