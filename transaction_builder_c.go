package api

// #cgo CFLAGS: -I${SRCDIR}/include
// #cgo darwin LDFLAGS: ${SRCDIR}/include/libmobilecoin.a -framework Security -framework Foundation
// #cgo linux LDFLAGS: ${SRCDIR}/include/libmobilecoin_linux.a -lm -ldl
// #include <stdio.h>
// #include <stdlib.h>
// #include <errno.h>
// #include "libmobilecoin.h"
import "C"
import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/bwesterb/go-ristretto"
	account "github.com/jadeydi/mobilecoin-account"
)

// mc_transaction_builder_create
func MCTransactionBuilderCreate(inputCs []*InputC, amount, fee, tombstone uint64, version uint32, recipient *account.PublicAddress, change *account.Account) error {
	verifier, err := C.mc_verifier_create()
	if err != nil {
		return err
	}
	defer C.mc_verifier_free(verifier)

	fog_resolver, err := C.mc_fog_resolver_create(verifier)
	if err != nil {
		return err
	}
	defer C.mc_fog_resolver_free(fog_resolver)

	memo_builder, err := C.mc_memo_builder_default_create()
	if err != nil {
		return err
	}
	defer C.mc_memo_builder_free(memo_builder)

	transaction_builder, err := C.mc_transaction_builder_create(C.uint64_t(fee), C.uint64_t(tombstone), fog_resolver, memo_builder, C.uint32_t(version))
	if err != nil {
		return err
	}
	defer C.mc_transaction_builder_free(transaction_builder)

	// add input
	for _, input := range inputCs {
		view_private_key_bytes := C.CBytes(input.ViewPrivate.Bytes())
		defer C.free(view_private_key_bytes)
		view_private_key := C.McBuffer{
			buffer: (*C.uint8_t)(view_private_key_bytes),
			len:    C.size_t(len(view_private_key_bytes)),
		}

		subaddress_spend_private_key_bytes := C.CBytes(input.SubAddressSpendPrivate.Bytes())
		defer C.free(subaddress_spend_private_key_bytes)
		subaddress_spend_private_key := C.McBuffer{
			buffer: (*C.uint8_t)(subaddress_spend_private_key_bytes),
			len:    C.size_t(len(subaddress_spend_private_key_bytes)),
		}

		ring, err := C.mc_transaction_builder_ring_create()
		if err != nil {
			return err
		}
		defer C.mc_transaction_builder_ring_free(ring)

		for _, r := range input.TxOutWithProofCs {
			txOutBytes := []byte(r.TxOut.String())
			tx_out_proto_bytes := C.CBytes(txOutBytes)
			defer C.free(tx_out_proto_bytes)
			tx_out_proto := C.McBuffer{
				buffer: (*C.uint8_t)(tx_out_proto_bytes),
				len:    C.size_t(len(txOutBytes)),
			}
			proofBytes := []byte(r.TxOutMembershipProof.String())
			membership_proof_proto_bytes := C.CBytes(proofBytes)
			defer C.free(membership_proof_proto_bytes)
			membership_proof_proto := C.McBuffer{
				buffer: (*C.uint8_t)(membership_proof_proto_bytes),
				len:    C.size_t(len(proofBytes)),
			}
			b, err := C.mc_transaction_builder_ring_add_element(ring)
			if err != nil {
				return err
			} else if !b {
				return errors.New("mc_transaction_builder_ring_add_element failure")
			}
		}

		error_description_str := C.CString("")
		defer C.free(error_description_str)
		out_error := C.McError{
			error_code:        C.int(0),
			error_description: (*C.char)(error_description_str),
		}

		b, err := C.mc_transaction_builder_add_input(&transaction_builder, &view_private_key_bytes, &subaddress_spend_private_key_bytes, C.size_t(input.RealIndex), &ring, &out_error)
		if err != nil {
			return err
		} else if !b {
			return fmt.Errorf("mc_transaction_builder_add_input failure")
		}
	}

	// mc_transaction_builder_add_output
	report_url_recipient_str := C.CString(recipient.FogReportUrl)
	defer C.free(report_url_recipient_str)
	report_id_recipient_str := C.CString(recipient.FogReportId)
	defer C.free(report_id_recipient_str)
	sigBuf, err := hex.DecodeString(recipient.FogAuthoritySig)
	if err != nil {
		return nil, err
	}
	sig_bytes := C.CBytes(sigBuf)
	defer C.free(sig_bytes)
	authority_sig := C.McBuffer{
		buffer: (*C.uint8_t)(sig_bytes),
		len:    C.size_t(len(sigBuf)),
	}
	fog_info := C.McPublicAddressFogInfo{
		report_url:    (*C.char)(report_url_recipient_str),
		report_id:     (*C.char)(report_id_recipient_str),
		authority_sig: authority_sig,
	}

	viewPublicKeyBuf, err := hex.DecodeString(recipient.ViewPublicKey)
	if err != nil {
		return nil, err
	}
	view_public_key_bytes := C.CBytes(viewPublicKeyBuf)
	defer C.free(view_public_key_bytes)
	view_public := C.McBuffer{
		buffer: (*C.uint8_t)(view_public_key_bytes),
		len:    C.size_t(len(viewPublicKeyBuf)),
	}

	spendPublicKeyBuf, err := hex.DecodeString(recipient.SpendPublicKey)
	if err != nil {
		return nil, err
	}
	spend_public_key_bytes := C.CBytes(spendPublicKeyBuf)
	defer C.free(spend_public_key_bytes)
	spend_public := C.McBuffer{
		buffer: (*C.uint8_t)(spend_public_key_bytes),
		len:    C.size_t(len(spendPublicKeyBuf)),
	}

	recipient_address := &c.McPublicAddress{
		view_public_key:  view_public,
		spend_public_key: spend_public,
		fog_info:         fog_info,
	}

	var rRecipient ristretto.Scalar
	rRecipient.Rand()
	viewPublicKeyRecipient := hexToPoint(recipient.ViewPublicKey)
	secretRecipient := createSharedSecret(viewPublicKeyRecipient, &rRecipient)
	secret_recipient_bytes := C.CBytes(secretRecipient.Bytes())
	defer C.free(secret_recipient_bytes)
	out_tx_out_shared_secret := &C.McMutableBuffer{
		buffer: (*C.uint8_t)(secret_recipient_bytes),
		len:    C.size_t(len(secretRecipient.Bytes())),
	}

	confirmationRecipientBuf := ConfirmationNumberFromSecret(secretRecipient)
	confirmation_recipient_bytes := C.CBytes(confirmationRecipientBuf)
	defer C.free(confirmation_recipient_bytes)
	out_tx_out_confirmation_number := &C.McMutableBuffer{
		buffer: (*C.uint8_t)(confirmation_recipient_bytes),
		len:    C.size_t(len(confirmationRecipientBuf)),
	}

	var rng_callback *C.McRngCallback
	var out_error *C.McError
	_, err = C.mc_transaction_builder_add_output(transaction_builder, C.uint64_t(amount), recipient_address, rng_callback, out_tx_out_confirmation_number, out_tx_out_shared_secret, out_error)
	if err != nil {
		return nil, err
	}
	// mc_transaction_builder_add_change_output
}

func hexToBuf(text string) []byte {
	buf, err := hex.DecodeString(text)
	if err != nil {
		panic(err)
	}
	return buf
}
