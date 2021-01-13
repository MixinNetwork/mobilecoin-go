package api

import (
	"encoding/hex"
	"fmt"

	"github.com/bwesterb/go-ristretto"
	"github.com/gtank/merlin"
)

type PseudoOutputValuesAndBlindings struct {
	Value    uint64
	Blinding *ristretto.Scalar
}

func SignRctBulletproofs(message []byte, inputs []*InputCredential, fee uint64, outputWithSharedSecrets []*OutputAndSharedSecret) (*SignatureRctBulletproofs, error) {
	pseudoOutputBlindings := make([]*ristretto.Scalar, len(inputs)-1)
	for i := 0; i < len(inputs)-1; i++ {
		var r ristretto.Scalar
		pseudoOutputBlindings[i] = r.Rand()
	}

	var sumOfOutputBlindings ristretto.Scalar
	sumOfOutputBlindings.SetZero()
	for i := range outputWithSharedSecrets {
		_, blinding := outputWithSharedSecrets[i].GetValueWithBlinding()
		sumOfOutputBlindings.Add(&sumOfOutputBlindings, blinding)
	}

	var sumOfPseudoOutputBlindings ristretto.Scalar
	sumOfPseudoOutputBlindings.SetZero()
	for i := range pseudoOutputBlindings {
		sumOfPseudoOutputBlindings.Add(&sumOfPseudoOutputBlindings, pseudoOutputBlindings[i])
	}

	var lastBlinding ristretto.Scalar
	lastBlinding.Sub(&sumOfOutputBlindings, &sumOfPseudoOutputBlindings)
	pseudoOutputBlindings = append(pseudoOutputBlindings, &lastBlinding)

	// input_secrets.push((onetime_private_key, value, blinding));
	var pseudoOutputValuesAndBlindings []*PseudoOutputValuesAndBlindings
	for i, input := range inputs {
		value, _ := GetValueWithBlinding(inputs[i].Ring[input.RealIndex], inputs[i].ViewPrivateKey)
		p := &PseudoOutputValuesAndBlindings{
			Value:    value,
			Blinding: pseudoOutputBlindings[i],
		}
		pseudoOutputValuesAndBlindings = append(pseudoOutputValuesAndBlindings, p)
	}

	// GenerateRangeProofs
	values := make([]uint64, len(pseudoOutputValuesAndBlindings))
	blindings := make([]*ristretto.Scalar, len(pseudoOutputValuesAndBlindings))
	for i := range pseudoOutputValuesAndBlindings {
		values[i] = pseudoOutputValuesAndBlindings[i].Value
		blindings[i] = pseudoOutputValuesAndBlindings[i].Blinding
	}
	for i := range outputWithSharedSecrets {
		value, blinding := outputWithSharedSecrets[i].GetValueWithBlinding()
		values = append(values, value)
		blindings = append(blindings, blinding)
	}

	bpGens := NewBulletproofGens(64, 64)
	pcGens := NewPedersenGens()
	range_proof, commitments, err := GenerateRangeProofs(bpGens, pcGens, values, blindings)
	if err != nil {
		return nil, err
	}

	// check_value_is_preserved

	pseudoOutputCommitments := commitments[:len(inputs)]
	pseudo_output_commitments := make([]string, len(pseudoOutputCommitments))
	for i := range pseudoOutputCommitments {
		pseudo_output_commitments[i] = hex.EncodeToString(pseudoOutputCommitments[i].Bytes())
	}

	range_proof_bytes := range_proof.ToBytes()
	extended_message := make([]byte, 0)
	extended_message = append(extended_message, message...)
	for i := range pseudoOutputCommitments {
		extended_message = append(extended_message, pseudoOutputCommitments[i].Bytes()...)
	}
	extended_message = append(extended_message, range_proof_bytes...)

	var ring_signatures []*RingMLSAG
	for i, input := range inputs {
		value, blinding := GetValueWithBlinding(inputs[i].Ring[input.RealIndex], inputs[i].ViewPrivateKey)
		ring_signature, err := signRing(extended_message, inputs[i].Ring, inputs[i].RealIndex, inputs[i].OnetimePrivateKey, value, blinding, pseudoOutputBlindings[i])
		if err != nil {
			return nil, err
		}
		ring_signatures = append(ring_signatures, ring_signature)
	}

	return &SignatureRctBulletproofs{
		RangeProofs:             hex.EncodeToString(range_proof_bytes),
		PseudoOutputCommitments: pseudo_output_commitments,
		RingSignatures:          ring_signatures,
	}, nil
}

type RangeProof struct {
	A, S       *ristretto.Point
	T1, T2     *ristretto.Point
	TX         *ristretto.Scalar
	TXBlinding *ristretto.Scalar
	EBlinding  *ristretto.Scalar
	IPPProof   *InnerProductProof
}

func (p *RangeProof) ToBytes() []byte {
	var buf []byte
	buf = append(buf, p.A.Bytes()...)
	buf = append(buf, p.S.Bytes()...)
	buf = append(buf, p.T1.Bytes()...)
	buf = append(buf, p.T2.Bytes()...)
	buf = append(buf, p.TX.Bytes()...)
	buf = append(buf, p.TXBlinding.Bytes()...)
	buf = append(buf, p.EBlinding.Bytes()...)
	buf = append(buf, p.IPPProof.ToBytes()...)

	return buf
}

func GenerateRangeProofs(bpGens *BulletproofGens, pcGens *PedersenGens, values []uint64, blindings []*ristretto.Scalar) (*RangeProof, []*ristretto.Point, error) {
	valuesPadded := resizeUint64ToPow2(values)
	blindingsPadded := resizeScalarToPow2(blindings)

	initial := InitialTranscript(BULLETPROOF_DOMAIN_TAG)
	transcript := InitialTranscript(BULLETPROOF_DOMAIN_TAG)

	return ProveMultipleWithRNG(bpGens, pcGens, initial, transcript, valuesPadded, blindingsPadded, 64)
}

// n = 64
func ProveMultipleWithRNG(
	BPGens *BulletproofGens,
	PCGens *PedersenGens,
	initial *merlin.Transcript,
	transcript *merlin.Transcript,
	values []uint64,
	blindings []*ristretto.Scalar,
	n int64,
) (*RangeProof, []*ristretto.Point, error) {
	if len(values) != len(blindings) {
		return nil, nil, fmt.Errorf("ProveMultipleWithRNG WrongNumBlindingFactors %d, %d", len(values), len(blindings))
	}

	dealer1 := NewDealer(BPGens, PCGens, initial, transcript, n, int64(len(values)))

	var err error
	parties := make([]*PartyAwaitingPosition, len(values))
	for i := range values {
		parties[i] = NewParty(BPGens, PCGens, values[i], blindings[i], n)
	}

	partiesA := make([]*PartyAwaitingBitChallenge, len(parties))
	bitCommitments := make([]*BitCommitment, len(parties))
	for j := range parties {
		partiesA[j], bitCommitments[j], err = parties[j].AssignPositionWithRNG(j)
		if err != nil {
			return nil, nil, err
		}
	}
	valueCommitments := make([]*ristretto.Point, len(bitCommitments))
	for i := range bitCommitments {
		valueCommitments[i] = bitCommitments[i].VJ
	}

	dealer2, bitChallenge, err := dealer1.ReceiveBitCommitments(bitCommitments)
	if err != nil {
		return nil, nil, err
	}

	partiesB := make([]*PartyAwaitingPolyChallenge, len(partiesA))
	polyCommitments := make([]*PolyCommitment, len(partiesA))
	for i := range partiesA {
		partiesB[i], polyCommitments[i] = partiesA[i].ApplyChallengeWithRNG(bitChallenge)
	}

	dealer3, polyChallenge := dealer2.ReceivePolyCommitments(polyCommitments)

	proofShares := make([]*ProofShare, len(partiesB))
	for i := range partiesB {
		proofShares[i], _ = partiesB[i].ApplyChallenge(polyChallenge)
	}

	proof := dealer3.AssembleShares(proofShares)
	return proof, valueCommitments, nil
}
