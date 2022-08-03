package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/bwesterb/go-ristretto"
	account "github.com/jadeydi/mobilecoin-account"
	"github.com/jadeydi/mobilecoin-account/types"
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
		ViewPrivateKey:      account.HexToScalar(viewPrivate),
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

type Output struct {
	TransactionHash string
	RawTransaction  string
	Fee             uint64
	OutputIndex     int64
	OutputHash      string
	ChangeIndex     int64
	ChangeHash      string
	ChangeAmount    uint64
}

func TransactionBuilderBuild(inputs []*UTXO, proofs *Proofs, output string, amount, fee uint64, changePrivate string, tombstone uint64, tokenID, version uint) (*Output, error) {
	recipient, err := account.DecodeB58Code(output)
	if err != nil {
		return nil, err
	}
	if len(changePrivate) != 128 {
		return nil, errors.New("invalid change private")
	}
	change, err := account.NewAccountKey(changePrivate[:64], changePrivate[64:])
	if err != nil {
		return nil, err
	}

	var totalAmount uint64 = 0
	unspentList := make([]*UnspentTxOut, len(inputs))
	for i, input := range inputs {
		totalAmount += input.Amount

		data, err := hex.DecodeString(input.ScriptPubKey)
		if err != nil {
			return nil, err
		}
		var txOut TxOut
		err = json.Unmarshal(data, &txOut)
		if err != nil {
			return nil, err
		}

		onetimePrivateKey, err := RecoverOnetimePrivateKey(txOut.PublicKey, input.PrivateKey)
		if err != nil {
			return nil, err
		}
		image := hex.EncodeToString(KeyImageFromPrivate(onetimePrivateKey).Bytes())
		unspentList[i] = &UnspentTxOut{
			TxOut:                   &txOut,
			SubaddressIndex:         0,
			KeyImage:                image,
			Value:                   fmt.Sprint(input.Amount),
			AttemptedSpendHeight:    0,
			AttemptedSpendTombstone: 0,
			MonitorId:               "",
		}
	}

	changeAmount := totalAmount - amount - fee
	if changeAmount <= MILLIMOB_TO_PICOMOB {
		changeAmount = 0
		fee += changeAmount
	}
	if changeAmount > 0 && changeAmount <= MILLIMOB_TO_PICOMOB {
		return nil, errors.New("invalid change amount")
	}
	if totalAmount != (amount + fee + changeAmount) {
		return nil, errors.New("invalid amount")
	}
	inputCs, err := BuildRingElements(inputs, proofs)
	if err != nil {
		return nil, err
	}

	var randomPrivateOut ristretto.Scalar
	randomPrivateOut.Rand()
	var randomPrivateChange ristretto.Scalar
	randomPrivateChange.Rand()
	txC, err := MCTransactionBuilderCreateC(inputCs, amount, changeAmount, fee, tombstone, tokenID, version, recipient, change, &randomPrivateOut, &randomPrivateChange)
	if err != nil {
		return nil, err
	}

	size := 1
	if changeAmount > 0 {
		size = 2
	}
	hashOutput := hex.EncodeToString(createTxPublicKey(&randomPrivateOut, account.HexToPoint(recipient.SpendPublicKey)).Bytes())
	outlayList := make([]*Outlay, size)
	outlayIndexToTxOutIndex := make([][]int, size)
	outlayConfirmationNumbers := make([][]int, size)

	outlayList[0] = &Outlay{
		Value:    fmt.Sprint(amount),
		Receiver: recipient,
	}
	outlayIndexToTxOutIndex[0] = []int{0, 0}
	viewOut := account.HexToPoint(recipient.ViewPublicKey)
	secretOut := createSharedSecret(viewOut, &randomPrivateOut)
	confirmationOut := ConfirmationNumberFromSecret(secretOut)
	numsOut := make([]int, len(confirmationOut))
	for i, b := range confirmationOut {
		numsOut[i] = int(b)
	}
	outlayConfirmationNumbers[0] = numsOut

	var hashChange string
	if changeAmount > 0 {
		changeAddress := change.PublicAddress(0)
		hashChange = hex.EncodeToString(createTxPublicKey(&randomPrivateChange, account.HexToPoint(changeAddress.SpendPublicKey)).Bytes())
		outlayList[1] = &Outlay{
			Value:    fmt.Sprint(changeAmount),
			Receiver: recipient,
		}
		outlayIndexToTxOutIndex[1] = []int{1, 1}
		viewChange := account.HexToPoint(changeAddress.ViewPublicKey)
		secretChange := createSharedSecret(viewChange, &randomPrivateChange)
		confirmationChange := ConfirmationNumberFromSecret(secretChange)
		numsChange := make([]int, len(confirmationChange))
		for i, b := range confirmationChange {
			numsChange[i] = int(b)
		}
		outlayConfirmationNumbers[1] = numsChange
	}
	tx := UnmarshalTx(txC)

	txProposal := TxProposal{
		InputList:                 unspentList,
		OutlayList:                outlayList,
		Tx:                        tx,
		Fee:                       fee,
		OutlayIndexToTxOutIndex:   outlayIndexToTxOutIndex,
		OutlayConfirmationNumbers: outlayConfirmationNumbers,
	}

	script, err := json.Marshal(txProposal)
	if err != nil {
		return nil, err
	}
	return &Output{
		TransactionHash: hashOutput,
		RawTransaction:  hex.EncodeToString(randomPrivateOut.Bytes()) + ":" + hex.EncodeToString(script),
		Fee:             fee,
		OutputIndex:     0,
		OutputHash:      hashOutput,
		ChangeIndex:     0,
		ChangeHash:      hashChange,
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
