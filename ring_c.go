package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/bwesterb/go-ristretto"
	account "github.com/jadeydi/mobilecoin-account"
	"github.com/jadeydi/mobilecoin-account/types"
)

type TxOutWithProofC struct {
	TxOut                *types.TxOut
	TxOutMembershipProof *types.TxOutMembershipProof
}

type InputC struct {
	ViewPrivate            *ristretto.Scalar
	SubAddressSpendPrivate *ristretto.Scalar
	RealIndex              int
	TxOutWithProofCs       []*TxOutWithProofC
}

// mc_transaction_builder_ring_add_element
func BuildRingElements(utxos []*UTXO, proofs *Proofs) ([]*InputC, error) {
	inputSet := make(map[string]*UTXO)
	for _, utxo := range utxos {
		if len(utxo.ScriptPubKey) < 8 {
			return nil, fmt.Errorf("MobileCoin invalid script pub key %s", utxo.ScriptPubKey)
		}
		data, err := hex.DecodeString(utxo.ScriptPubKey)
		if err != nil {
			return nil, err
		}
		var txOut TxOut
		err = json.Unmarshal(data, &txOut)
		if err != nil {
			return nil, err
		}
		inputSet[txOut.PublicKey] = utxo
	}

	var inputCs []*InputC
	if len(proofs.Ring) == 0 || len(proofs.Ring) != len(proofs.Rings) {
		return nil, fmt.Errorf("Invalid proofs ring len %d, rings len %d", len(proofs.Rings), len(proofs.Ring))
	}
	for i, itemi := range proofs.Ring {
		index := 0
		ring := proofs.Rings[i]
		for j, itemj := range ring {
			if itemi.TxOut.PublicKey == itemj.TxOut.PublicKey {
				index = j
				break
			}
		}
		if index == 0 {
			ring[index] = itemi
		}

		var txOutWithProofCs []*TxOutWithProofC
		for _, item := range ring {
			txOutWithProofCs = append(txOutWithProofCs, &TxOutWithProofC{
				TxOut:                MarshalTxOut(item.TxOut),
				TxOutMembershipProof: MarshalTxOutMembershipProof(item.Proof),
			})
		}
		sort.Slice(txOutWithProofCs, func(i, j int) bool {
			return bytes.Compare(txOutWithProofCs[i].TxOut.PublicKey.GetData(), txOutWithProofCs[j].TxOut.PublicKey.GetData()) == -1
		})

		for j, itemj := range txOutWithProofCs {
			if itemi.TxOut.PublicKey == hex.EncodeToString(itemj.TxOut.PublicKey.GetData()) {
				index = j
				break
			}
		}
		if inputSet[itemi.TxOut.PublicKey] == nil {
			return nil, fmt.Errorf("UTXO did not find")
		}
		source := inputSet[itemi.TxOut.PublicKey].PrivateKey
		acc, err := account.NewAccountKey(source[:64], source[64:])
		if err != nil {
			return nil, err
		}
		inputCs = append(inputCs, &InputC{
			ViewPrivate:            hexToScalar(source[:64]),
			SubAddressSpendPrivate: acc.SubaddressSpendPrivateKey(0),
			RealIndex:              index,
			TxOutWithProofCs:       txOutWithProofCs,
		})
	}
	return inputCs, nil
}

func MarshalTxOut(input *TxOut) *types.TxOut {
	return &types.TxOut{
		MaskedAmount: &types.MaskedAmount{
			Commitment: &types.CompressedRistretto{
				Data: account.HexToBytes(input.Amount.Commitment),
			},
			MaskedValue:   uint64(input.Amount.MaskedValue),
			MaskedTokenId: account.HexToBytes(input.Amount.MaskedTokenID),
		},
		TargetKey: &types.CompressedRistretto{
			Data: hexToPoint(input.TargetKey).Bytes(),
		},
		PublicKey: &types.CompressedRistretto{
			Data: hexToPoint(input.PublicKey).Bytes(),
		},
		EFogHint: &types.EncryptedFogHint{
			Data: account.HexToBytes(input.EFogHint),
		},
		EMemo: &types.EncryptedMemo{
			Data: account.HexToBytes(input.EMemo),
		},
	}
}

func MarshalTxOutMembershipProof(proof *TxOutMembershipProof) *types.TxOutMembershipProof {
	var elements []*types.TxOutMembershipElement
	for _, e := range proof.Elements {
		elements = append(elements, &types.TxOutMembershipElement{
			Range: &types.Range{
				From: stringToUint64(e.Range.From),
				To:   stringToUint64(e.Range.To),
			},
			Hash: &types.TxOutMembershipHash{
				Data: account.HexToBytes(e.Hash),
			},
		})
	}
	return &types.TxOutMembershipProof{
		Index:        stringToUint64(proof.Index),
		HighestIndex: stringToUint64(proof.HighestIndex),
		Elements:     elements,
	}
}

func stringToUint64(v string) uint64 {
	i, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		panic(err)
	}
	return i
}
