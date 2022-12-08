package api

import (
	"encoding/hex"
	"errors"
	"fmt"

	account "github.com/MixinNetwork/mobilecoin-account"
	"github.com/MixinNetwork/mobilecoin-account/types"
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
	MOB_MINIMUM_FEE                      = 400_000_000
	MINIMUM_EUSD                         = 1_000_000

	MAX_TOMBSTONE_BLOCKS = 20160
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

type Output struct {
	TransactionHash string
	RawTransaction  string
	SharedSecret    string
	Fee             uint64
	OutputIndex     int64
	OutputHash      string
	ChangeIndex     int64
	ChangeHash      string
	ChangeAmount    uint64
}

func TransactionBuilderBuild(inputs []*UTXO, proofs *Proofs, output string, amount, fee uint64, tombstone, memo uint64, tokenID, version uint, changeStr string) (*Output, error) {
	recipient, err := account.DecodeB58Code(output)
	if err != nil {
		return nil, err
	}
	change, err := account.DecodeB58Code(changeStr)
	if err != nil {
		return nil, err
	}

	var totalAmount uint64
	for _, input := range inputs {
		totalAmount += input.Amount
	}

	changeAmount := totalAmount - amount - fee
	if changeAmount < MOB_MINIMUM_FEE {
		changeAmount = 0
		fee += changeAmount
	}
	if changeAmount > 0 && changeAmount < MILLIMOB_TO_PICOMOB {
		return nil, errors.New("invalid change amount")
	}
	if totalAmount != (amount + fee + changeAmount) {
		return nil, errors.New("invalid amount")
	}
	inputCs, err := BuildRingElements(inputs, proofs)
	if err != nil {
		return nil, err
	}

	txC, err := MCTransactionBuilderCreateC(inputCs, amount, changeAmount, fee, tombstone, memo, tokenID, version, recipient, change)
	if err != nil {
		return nil, err
	}

	return &Output{
		TransactionHash: hex.EncodeToString(txC.TxOut.PublicKey.GetData()),
		RawTransaction:  hex.EncodeToString(txC.Tx),
		SharedSecret:    hex.EncodeToString(txC.ShareSecretOut),
		Fee:             fee,
		OutputIndex:     0,
		OutputHash:      hex.EncodeToString(txC.TxOut.PublicKey.GetData()),
		ChangeIndex:     0,
		ChangeHash:      hex.EncodeToString(txC.TxOutChange.PublicKey.GetData()),
		ChangeAmount:    changeAmount,
	}, nil
}

func UnmarshalTx(tx *types.Tx) *Tx {
	return &Tx{
		Prefix:    UnmarshalPrefix(tx.Prefix),
		Signature: UnmarshalSignatureRctBulletproofs(tx.Signature),
	}
}

func UnmarshalPrefix(prefix *types.TxPrefix) *TxPrefix {
	ins := make([]*TxIn, len(prefix.Inputs))
	for i, in := range prefix.Inputs {
		ring := make([]*TxOut, len(in.Ring))
		for i, r := range in.Ring {
			ring[i] = UnmarshalTxOut(r)
		}
		proofs := make([]*TxOutMembershipProof, len(in.Proofs))
		for i, p := range in.Proofs {
			proofs[i] = UnmarshalTxOutMembershipProof(p)
		}
		ins[i] = &TxIn{
			Ring:   ring,
			Proofs: proofs,
		}
	}

	outs := make([]*TxOut, len(prefix.Outputs))
	for i, out := range prefix.Outputs {
		outs[i] = UnmarshalTxOut(out)
	}

	return &TxPrefix{
		Inputs:         ins,
		Outputs:        outs,
		Fee:            FeeValue(prefix.Fee),
		TombstoneBlock: TombstoneValue(prefix.TombstoneBlock),
	}
}

func UnmarshalTxOut(out *types.TxOut) *TxOut {
	return &TxOut{
		Amount: &Amount{
			Commitment:    hex.EncodeToString(out.MaskedAmount.Commitment.GetData()),
			MaskedValue:   MaskedValue(out.MaskedAmount.MaskedValue),
			MaskedTokenID: hex.EncodeToString(out.MaskedAmount.MaskedTokenId),
		},
		TargetKey: hex.EncodeToString(out.TargetKey.GetData()),
		PublicKey: hex.EncodeToString(out.PublicKey.GetData()),
		EFogHint:  hex.EncodeToString(out.EFogHint.GetData()),
		EMemo:     hex.EncodeToString(out.EMemo.GetData()),
	}
}

func UnmarshalTxOutMembershipProof(proof *types.TxOutMembershipProof) *TxOutMembershipProof {
	elements := make([]*TxOutMembershipElement, len(proof.Elements))
	for i, e := range proof.Elements {
		elements[i] = &TxOutMembershipElement{
			Range: &Range{
				From: fmt.Sprint(e.Range.From),
				To:   fmt.Sprint(e.Range.To),
			},
			Hash: hex.EncodeToString(e.Hash.GetData()),
		}
	}
	return &TxOutMembershipProof{
		Index:        fmt.Sprint(proof.Index),
		HighestIndex: fmt.Sprint(proof.HighestIndex),
		Elements:     elements,
	}
}

func UnmarshalSignatureRctBulletproofs(signature *types.SignatureRctBulletproofs) *SignatureRctBulletproofs {
	signatures := make([]*RingMLSAG, len(signature.RingSignatures))
	for i, s := range signature.RingSignatures {
		signatures[i] = UnmarshalRingMLSAG(s)
	}
	commitments := make([]string, len(signature.PseudoOutputCommitments))
	for i, c := range signature.PseudoOutputCommitments {
		commitments[i] = hex.EncodeToString(c.GetData())
	}
	return &SignatureRctBulletproofs{
		RingSignatures:          signatures,
		PseudoOutputCommitments: commitments,
		RangeProofs:             hex.EncodeToString(signature.RangeProofBytes),
	}
}

func UnmarshalRingMLSAG(mlsag *types.RingMLSAG) *RingMLSAG {
	responses := make([]string, len(mlsag.Responses))
	for i, resp := range mlsag.Responses {
		responses[i] = hex.EncodeToString(resp.GetData())
	}
	return &RingMLSAG{
		CZero:     hex.EncodeToString(mlsag.CZero.GetData()),
		Responses: responses,
		KeyImage:  hex.EncodeToString(mlsag.KeyImage.GetData()),
	}
}
