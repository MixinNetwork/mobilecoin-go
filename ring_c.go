package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/MixinNetwork/mobilecoin-go/types"
	"github.com/bwesterb/go-ristretto"
	account "github.com/jadeydi/mobilecoin-account"
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
func BuildRingElements(viewPrivate string, utxos []*UTXO, proofs *Proofs) ([]*InputC, error) {
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

		sort.Slice(ring, func(i, j int) bool {
			return ring[i].TxOut.PublicKey < ring[j].TxOut.PublicKey
		})

		for j, itemj := range ring {
			if itemi.TxOut.PublicKey == itemj.TxOut.PublicKey {
				index = j
				break
			}
		}
		var txOutWithProofCs []*TxOutWithProofC
		for _, item := range ring {
			bytesA, err := json.Marshal(item.TxOut)
			if err != nil {
				return nil, err
			}
			bytesB, err := json.Marshal(item.Proof)
			if err != nil {
				return nil, err
			}
			var txOutC types.TxOut
			err = json.Unmarshal(bytesA, &txOutC)
			if err != nil {
				return nil, err
			}
			var txOutMembershipProofC types.TxOutMembershipProof
			err = json.Unmarshal(bytesB, &txOutMembershipProofC)
			if err != nil {
				return nil, err
			}
			txOutWithProofCs = append(txOutWithProofCs, &TxOutWithProofC{
				TxOut:                &txOutC,
				TxOutMembershipProof: &txOutMembershipProofC,
			})
		}
		if inputSet[itemi.TxOut.PublicKey] == nil {
			return nil, fmt.Errorf("UTXO did not find")
		}
		acc, err := account.NewAccountKey(viewPrivate, inputSet[itemi.TxOut.PublicKey].PrivateKey)
		if err != nil {
			return nil, err
		}
		inputCs = append(inputCs, &InputC{
			ViewPrivate:            hexToScalar(viewPrivate),
			SubAddressSpendPrivate: acc.SubaddressSpendPrivateKey(0),
			RealIndex:              index,
			TxOutWithProofCs:       txOutWithProofCs,
		})
	}
	return inputCs, nil
}
