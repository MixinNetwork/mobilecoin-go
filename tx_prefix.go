package api

import (
	"encoding/binary"
	"encoding/hex"
	"strconv"

	"github.com/bwesterb/go-ristretto"
	"github.com/gtank/merlin"
)

const (
	PRIMITIVE     = "prim"
	SEQUENCE      = "seq"
	AGGREGATE     = "agg"
	AGGREGATE_END = "agg-end"
	VARIANT       = "var"
	NONE          = ""
)

// Convert tx_prefix to merlin transcript
func HashOfTxPrefix(tx *TxPrefix) []byte {
	t := merlin.NewTranscript("digestible")
	appendTxPrefix(tx, t)
	return t.ExtractBytes([]byte("digest32"), 32)
}

// TxIn: append transaction inputs to transcript
// TxOutMembershipProof: append membership proof to transcript
func appendIndex(index string, t *merlin.Transcript) {
	i, err := strconv.ParseUint(index, 10, 64)
	if err != nil {
		panic(err)
	}
	appendBytes([]byte("index"), []byte(PRIMITIVE), t)

	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, i)
	appendBytes([]byte("uint"), bytes, t)
}

func appendHighestIndex(index string, t *merlin.Transcript) {
	i, err := strconv.ParseUint(index, 10, 64)
	if err != nil {
		panic(err)
	}
	appendBytes([]byte("highest_index"), []byte(PRIMITIVE), t)

	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, i)
	appendBytes([]byte("uint"), bytes, t)
}

func appendRange(r *Range, t *merlin.Transcript) {
	appendBytes([]byte("range"), []byte(AGGREGATE), t)
	appendBytes([]byte("name"), []byte("Range"), t)

	appendBytes([]byte("from"), []byte("prim"), t)
	i, err := strconv.ParseUint(r.From, 10, 64)
	if err != nil {
		panic(err)
	}
	bufi := make([]byte, 8)
	binary.LittleEndian.PutUint64(bufi, i)
	appendBytes([]byte("uint"), bufi, t)

	appendBytes([]byte("to"), []byte("prim"), t)
	j, err := strconv.ParseUint(r.To, 10, 64)
	if err != nil {
		panic(err)
	}
	bufj := make([]byte, 8)
	binary.LittleEndian.PutUint64(bufj, j)
	appendBytes([]byte("uint"), bufj, t)
	appendBytes([]byte("range"), []byte(AGGREGATE_END), t)
	appendBytes([]byte("name"), []byte("Range"), t)
}

func appendHash(hash string, t *merlin.Transcript) {
	appendBytes([]byte("hash"), []byte("prim"), t)

	buf, err := hex.DecodeString(hash)
	if err != nil {
		panic(err)
	}
	appendBytes([]byte("bytes"), buf, t)
}

func appendElement(element *TxOutMembershipElement, t *merlin.Transcript) {
	appendBytes([]byte(""), []byte(AGGREGATE), t)
	appendBytes([]byte("name"), []byte("TxOutMembershipElement"), t)

	appendRange(element.Range, t)
	appendHash(element.Hash, t)

	appendBytes([]byte(""), []byte(AGGREGATE_END), t)
	appendBytes([]byte("name"), []byte("TxOutMembershipElement"), t)
}

func appendElements(elements []*TxOutMembershipElement, t *merlin.Transcript) {
	appendBytes([]byte("elements"), []byte(SEQUENCE), t)
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, uint64(len(elements)))
	appendBytes([]byte("len"), bytes, t)

	for _, element := range elements {
		appendElement(element, t)
	}
}

// "Ring" of inputs, one of which is actually being spent.
func appendRing(outputs []*TxOut, t *merlin.Transcript) {
	appendBytes([]byte("ring"), []byte(SEQUENCE), t)

	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, uint64(len(outputs)))
	appendBytes([]byte("len"), bytes, t)

	for _, output := range outputs {
		appendTxOut(output, t)
	}
}

// Proof that each TxOut in `ring` is in the ledger.
func appendTxOutMembershipProof(proof *TxOutMembershipProof, t *merlin.Transcript) {
	appendBytes([]byte(""), []byte(AGGREGATE), t)
	appendBytes([]byte("name"), []byte("TxOutMembershipProof"), t)

	appendIndex(proof.Index, t)
	appendHighestIndex(proof.HighestIndex, t)
	appendElements(proof.Elements, t)

	appendBytes([]byte(""), []byte(AGGREGATE_END), t)
	appendBytes([]byte("name"), []byte("TxOutMembershipProof"), t)
}

func appendTxOutMembershipProofs(proofs []*TxOutMembershipProof, t *merlin.Transcript) {
	appendBytes([]byte("proofs"), []byte(SEQUENCE), t)

	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, uint64(len(proofs)))
	appendBytes([]byte("len"), bytes, t)

	for _, proof := range proofs {
		appendTxOutMembershipProof(proof, t)
	}
}

func appendTxIn(in *TxIn, t *merlin.Transcript) {
	appendBytes([]byte(""), []byte(AGGREGATE), t)
	appendBytes([]byte("name"), []byte("TxIn"), t)

	appendRing(in.Ring, t)
	appendTxOutMembershipProofs(in.Proofs, t)

	appendBytes([]byte(""), []byte(AGGREGATE_END), t)
	appendBytes([]byte("name"), []byte("TxIn"), t)
}

func appendInputs(inputs []*TxIn, t *merlin.Transcript) {
	appendBytes([]byte("inputs"), []byte(SEQUENCE), t)

	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, uint64(len(inputs)))
	appendBytes([]byte("len"), bytes, t)

	for _, input := range inputs {
		appendTxIn(input, t)
	}
}

// TxOut: append tx out to transcript

// Append TxOut Amount
func appendCommitment(commitment string, t *merlin.Transcript) {
	buf, err := hex.DecodeString(commitment)
	if err != nil {
		panic(err)
	}
	appendBytes([]byte("commitment"), []byte(PRIMITIVE), t)
	appendBytes([]byte("ristretto"), buf, t)
}

func appendMaskedValue(value MaskedValue, t *merlin.Transcript) {
	appendBytes([]byte("masked_value"), []byte(PRIMITIVE), t)

	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, uint64(value))
	appendBytes([]byte("uint"), bytes, t)
}

func appendAmount(amount *Amount, t *merlin.Transcript) {
	appendBytes([]byte("amount"), []byte(AGGREGATE), t)
	appendBytes([]byte("name"), []byte("Amount"), t)

	appendCommitment(amount.Commitment, t)
	appendMaskedValue(amount.MaskedValue, t)

	appendBytes([]byte("amount"), []byte(AGGREGATE_END), t)
	appendBytes([]byte("name"), []byte("Amount"), t)
}

// Append TxOut TargetKey
func appendTargetKey(key string, t *merlin.Transcript) {
	buf, err := hex.DecodeString(key)
	if err != nil {
		panic(err)
	}
	appendBytes([]byte("target_key"), []byte(PRIMITIVE), t)
	appendBytes([]byte("ristretto"), buf, t)
}

// Append TxOut PublicKey
func appendPublicKey(key string, t *merlin.Transcript) {
	buf, err := hex.DecodeString(key)
	if err != nil {
		panic(err)
	}
	appendBytes([]byte("public_key"), []byte(PRIMITIVE), t)
	appendBytes([]byte("ristretto"), buf, t)
}

// Append TxOut EFogHint
func appendEFogHint(hint string, t *merlin.Transcript) {
	buf, err := hex.DecodeString(hint)
	if err != nil {
		panic(err)
	}
	appendBytes([]byte("e_fog_hint"), []byte(PRIMITIVE), t)
	appendBytes([]byte("bytes"), buf, t)
}

func appendTxOut(txOut *TxOut, t *merlin.Transcript) {
	appendBytes([]byte(""), []byte(AGGREGATE), t)
	appendBytes([]byte("name"), []byte("TxOut"), t)

	appendAmount(txOut.Amount, t)
	appendTargetKey(txOut.TargetKey, t)
	appendPublicKey(txOut.PublicKey, t)
	appendEFogHint(txOut.EFogHint, t)

	appendBytes([]byte(""), []byte(AGGREGATE_END), t)
	appendBytes([]byte("name"), []byte("TxOut"), t)
}

func appendOutputs(outputs []*TxOut, t *merlin.Transcript) {
	appendBytes([]byte("outputs"), []byte(SEQUENCE), t)

	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, uint64(len(outputs)))
	appendBytes([]byte("len"), bytes, t)

	for _, output := range outputs {
		appendTxOut(output, t)
	}
}

// Fee: append fee to transcript
func appendFee(fee uint64, t *merlin.Transcript) {
	appendBytes([]byte("fee"), []byte("prim"), t)

	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, fee)
	appendBytes([]byte("uint"), bytes, t)
}

// Tombstone: append tombstone block to transcript
func appendTombstoneBlock(tombstone uint64, t *merlin.Transcript) {
	appendBytes([]byte("tombstone_block"), []byte("prim"), t)

	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, tombstone)
	appendBytes([]byte("uint"), bytes, t)
}

func appendTxPrefix(tx *TxPrefix, t *merlin.Transcript) {
	appendBytes([]byte("mobilecoin-tx-prefix"), []byte(AGGREGATE), t)
	appendBytes([]byte("name"), []byte("TxPrefix"), t)

	appendInputs(tx.Inputs, t)
	appendOutputs(tx.Outputs, t)
	appendFee(uint64(tx.Fee), t)
	appendTombstoneBlock(uint64(tx.TombstoneBlock), t)

	appendBytes([]byte("mobilecoin-tx-prefix"), []byte(AGGREGATE_END), t)
	appendBytes([]byte("name"), []byte("TxPrefix"), t)
}

func appendInt64(label string, i uint64, t *merlin.Transcript) {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, i)
	appendBytes([]byte(label), buf, t)
}

func InnerproductDomainSep(n uint64, t *merlin.Transcript) {
	appendBytes([]byte("dom-sep"), []byte("ipp v1"), t)

	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, n)
	appendBytes([]byte("n"), bytes, t)
}

func appendBytes(field, data []byte, t *merlin.Transcript) {
	t.AppendMessage(field, data)
}

func ChallengeScalar(label string, t *merlin.Transcript) *ristretto.Scalar {
	data := t.ExtractBytes([]byte(label), 64)
	var dataBytes [64]byte
	copy(dataBytes[:], data[:])

	var s ristretto.Scalar
	return s.SetReduced(&dataBytes)
}

func AppendScalar(label string, s *ristretto.Scalar, t *merlin.Transcript) {
	appendBytes([]byte(label), s.Bytes(), t)
}

func AppendPoint(label string, p *ristretto.Point, t *merlin.Transcript) {
	appendBytes([]byte(label), p.Bytes(), t)
}
