package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/bwesterb/go-ristretto"
)

const (
	BULLETPROOF_DOMAIN_TAG               = "mc_bulletproof_transcript"
	SUBADDRESS_DOMAIN_TAG                = "mc_subaddress"
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
	var txOutM TxOutM
	err = json.Unmarshal(data, &txOutM)
	if err != nil {
		return nil, err
	}
	maskedValue, err := strconv.ParseUint(txOutM.Amount.MaskedValue, 10, 64)
	if err != nil {
		return nil, err
	}
	txOut := &TxOut{
		Amount: &Amount{
			Commitment:  txOutM.Amount.Commitment,
			MaskedValue: maskedValue,
		},
		TargetKey: txOutM.TargetKey,
		PublicKey: txOutM.PublicKey,
		EFogHint:  txOutM.EFogHint,
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
			TxOut: txOut,
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
		ViewPrivateKey:      ViewPrivateKeyFromHex(viewPrivate),
		RealOutputPublicKey: realOutputPublicKey,
	}, nil
}

type OutputAndSharedSecret struct {
	Output       *TxOut           `json:"tx_out"`
	SharedSecret *ristretto.Point `json:"shared_secret"`
	Index        int
	Value        uint64
	Receiver     *PublicAddress
}

func (o *OutputAndSharedSecret) GetValueWithBlinding() (uint64, *ristretto.Scalar) {
	mask := GetValueMask(o.SharedSecret)
	maskedValue := o.Output.Amount.MaskedValue
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

func (tb *TransactionBuilder) Build() (*TxM, error) {
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

	outputList := make([]*TxOut, len(tb.OutputsAndSharedSecrets))
	for i := range tb.OutputsAndSharedSecrets {
		outputList[i] = tb.OutputsAndSharedSecrets[i].Output
	}

	txPrefix := &TxPrefix{
		Inputs:         inputList,
		Outputs:        outputList,
		Fee:            tb.Fee,
		TombstoneBlock: tb.TombstoneBlock,
	}

	message := HashOfTxPrefix(txPrefix)
	signatures, err := SignRctBulletproofs(message, tb.InputCredentials, tb.Fee, tb.OutputsAndSharedSecrets)
	if err != nil {
		return nil, err
	}

	inputListM := make([]*TxInM, len(inputList))
	for j := range inputList {
		ringM := make([]*TxOutM, len(inputList[j].Ring))
		for i := range inputList[j].Ring {
			txOut := inputList[j].Ring[i]
			ringM[i] = &TxOutM{
				Amount: &AmountM{
					Commitment:  txOut.Amount.Commitment,
					MaskedValue: fmt.Sprint(txOut.Amount.MaskedValue),
				},
				TargetKey: txOut.TargetKey,
				PublicKey: txOut.PublicKey,
				EFogHint:  txOut.EFogHint,
			}
		}
		inputListM[j] = &TxInM{
			Ring:   ringM,
			Proofs: inputList[j].Proofs,
		}
	}

	outputListM := make([]*TxOutM, len(txPrefix.Outputs))
	for i := range txPrefix.Outputs {
		txOut := txPrefix.Outputs[i]
		outputListM[i] = &TxOutM{
			Amount: &AmountM{
				Commitment:  txOut.Amount.Commitment,
				MaskedValue: fmt.Sprint(txOut.Amount.MaskedValue),
			},
			TargetKey: txOut.TargetKey,
			PublicKey: txOut.PublicKey,
			EFogHint:  txOut.EFogHint,
		}
	}

	txPrefixM := &TxPrefixM{
		Inputs:         inputListM,
		Outputs:        outputListM,
		Fee:            fmt.Sprint(tb.Fee),
		TombstoneBlock: fmt.Sprint(tb.TombstoneBlock),
	}

	return &TxM{
		Prefix:    txPrefixM,
		Signature: signatures,
	}, nil
}
