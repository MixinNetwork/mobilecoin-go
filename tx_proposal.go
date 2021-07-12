package api

import (
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"strconv"

	"github.com/MixinNetwork/mobilecoin-go/block"
	"github.com/btcsuite/btcutil/base58"
	"google.golang.org/protobuf/proto"
)

type MaskedValue uint64

func (mv MaskedValue) MarshalJSON() ([]byte, error) {
	s := strconv.FormatUint(uint64(mv), 10)
	return []byte(strconv.Quote(s)), nil
}

func (mv *MaskedValue) UnmarshalJSON(data []byte) error {
	dd, err := strconv.Unquote(string(data))
	if err != nil {
		return err
	}
	u, err := strconv.ParseUint(dd, 10, 64)
	if err != nil {
		return err
	}
	*mv = MaskedValue(u)
	return nil
}

type FeeValue uint64

func (fv FeeValue) MarshalJSON() ([]byte, error) {
	s := strconv.FormatUint(uint64(fv), 10)
	return []byte(strconv.Quote(s)), nil
}

func (fv *FeeValue) UnmarshalJSON(data []byte) error {
	dd, err := strconv.Unquote(string(data))
	if err != nil {
		return err
	}
	u, err := strconv.ParseUint(dd, 10, 64)
	if err != nil {
		return err
	}
	*fv = FeeValue(u)
	return nil
}

type TombstoneValue uint64

func (tv TombstoneValue) MarshalJSON() ([]byte, error) {
	s := strconv.FormatUint(uint64(tv), 10)
	return []byte(strconv.Quote(s)), nil
}

func (tv *TombstoneValue) UnmarshalJSON(data []byte) error {
	dd, err := strconv.Unquote(string(data))
	if err != nil {
		return err
	}
	u, err := strconv.ParseUint(dd, 10, 64)
	if err != nil {
		return err
	}
	*tv = TombstoneValue(u)
	return nil
}

type Amount struct {
	Commitment  string      `json:"commitment"`
	MaskedValue MaskedValue `json:"masked_value"`
}

type TxOut struct {
	Amount    *Amount `json:"amount"`
	TargetKey string  `json:"target_key"`
	PublicKey string  `json:"public_key"`
	EFogHint  string  `json:"e_fog_hint"`
}

type Range struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type TxOutMembershipElement struct {
	Range *Range `json:"range"`
	Hash  string `json:"hash"`
}

type TxOutMembershipProof struct {
	Index        string                    `json:"index"`
	HighestIndex string                    `json:"highest_index"`
	Elements     []*TxOutMembershipElement `json:"elements"`
}

type TxOutWithProof struct {
	TxOut *TxOut                `json:"tx_out"`
	Proof *TxOutMembershipProof `json:"proof"`
}

type Proofs struct {
	Ring  []*TxOutWithProof   `json:"ring"`
	Rings [][]*TxOutWithProof `json:"rings"`
}

type TxIn struct {
	Ring   []*TxOut                `json:"ring"`
	Proofs []*TxOutMembershipProof `json:"proofs"`
}

type TxPrefix struct {
	Inputs         []*TxIn        `json:"inputs"`
	Outputs        []*TxOut       `json:"outputs"`
	Fee            FeeValue       `json:"fee"`
	TombstoneBlock TombstoneValue `json:"tombstone_block"`
}

type RingMLSAG struct {
	CZero     string   `json:"c_zero"`
	Responses []string `json:"responses"`
	KeyImage  string   `json:"key_image"`
}

type SignatureRctBulletproofs struct {
	RingSignatures          []*RingMLSAG `json:"ring_signatures"`
	PseudoOutputCommitments []string     `json:"pseudo_output_commitments"`
	RangeProofs             string       `json:"range_proofs"`
}

type Tx struct {
	Prefix    *TxPrefix                 `json:"prefix"`
	Signature *SignatureRctBulletproofs `json:"signature"`
}

type UnspentTxOut struct {
	TxOut                   *TxOut `json:"tx_out"`
	SubaddressIndex         uint64 `json:"subaddress_index"`
	KeyImage                string `json:"key_image"`
	Value                   string `json:"value"`
	AttemptedSpendHeight    uint64 `json:"attempted_spend_height"`
	AttemptedSpendTombstone uint64 `json:"attempted_spend_tombstone"`
	MonitorId               string `json:"monitor_id"`
}

type PublicAddress struct {
	ViewPublicKey   string `json:"view_public_key"`
	SpendPublicKey  string `json:"spend_public_key"`
	FogReportUrl    string `json:"fog_report_url"`
	FogReportId     string `json:"fog_report_id"`
	FogAuthoritySig string `json:"fog_authority_sig"`
}

type Outlay struct {
	Value    string         `json:"value"`
	Receiver *PublicAddress `json:"receiver"`
}

type TxProposal struct {
	InputList                 []*UnspentTxOut `json:"input_list"`
	OutlayList                []*Outlay       `json:"outlay_list"`
	Tx                        *Tx             `json:"tx"`
	Fee                       uint64          `json:"fee"`
	OutlayIndexToTxOutIndex   [][]int         `json:"outlay_index_to_tx_out_index"`
	OutlayConfirmationNumbers [][]int         `json:"outlay_confirmation_numbers"`
}

func (addr *PublicAddress) B58Code() (string, error) {
	view, err := hex.DecodeString(addr.ViewPublicKey)
	if err != nil {
		return "", err
	}
	spend, err := hex.DecodeString(addr.SpendPublicKey)
	if err != nil {
		return "", err
	}
	address := &block.PublicAddress{
		ViewPublicKey:  &block.CompressedRistretto{Data: view},
		SpendPublicKey: &block.CompressedRistretto{Data: spend},
	}
	wrapper := &block.PrintableWrapper_PublicAddress{PublicAddress: address}
	data, err := proto.Marshal(&block.PrintableWrapper{Wrapper: wrapper})
	if err != nil {
		return "", err
	}

	bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes, crc32.ChecksumIEEE(data))
	bytes = append(bytes, data...)
	return base58.Encode(bytes), nil
}
