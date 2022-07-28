package api

// #cgo CFLAGS: -I${SRCDIR}/include
// #cgo darwin LDFLAGS: ${SRCDIR}/include/libmobilecoin.a -framework Security -framework Foundation
// #cgo linux LDFLAGS: ${SRCDIR}/include/libmobilecoin_linux.a -lm -ldl -lz
// #include <stdio.h>
// #include <stdlib.h>
// #include <errno.h>
// #include "libmobilecoin.h"
import "C"
import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"unsafe"

	"github.com/bwesterb/go-ristretto"
	account "github.com/jadeydi/mobilecoin-account"
	"google.golang.org/protobuf/proto"
)

// mc_transaction_builder_create
func MCTransactionBuilderCreate(inputCs []*InputC, amount, changeAmount, fee, tombstone uint64, version uint, recipient *account.PublicAddress, change *account.Account) error {
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
	if transaction_builder == nil {
		return errors.New("mc_transaction_builder_create error")
	}
	defer C.mc_transaction_builder_free(transaction_builder)

	// add input
	for _, input := range inputCs {
		view_private_input_buf := input.ViewPrivate.Bytes()
		view_private_key_bytes := C.CBytes(view_private_input_buf)
		defer C.free(view_private_key_bytes)
		view_private_key := &C.McBuffer{
			buffer: (*C.uint8_t)(view_private_key_bytes),
			len:    C.size_t(len(view_private_input_buf)),
		}

		subaddress_spend_private_buf := input.SubAddressSpendPrivate.Bytes()
		subaddress_spend_private_key_bytes := C.CBytes(subaddress_spend_private_buf)
		defer C.free(subaddress_spend_private_key_bytes)
		subaddress_spend_private_key := &C.McBuffer{
			buffer: (*C.uint8_t)(subaddress_spend_private_key_bytes),
			len:    C.size_t(len(subaddress_spend_private_buf)),
		}

		ring, err := C.mc_transaction_builder_ring_create()
		if err != nil {
			return err
		}
		defer C.mc_transaction_builder_ring_free(ring)

		for _, r := range input.TxOutWithProofCs {
			tx_out_buf, err := proto.Marshal(r.TxOut)
			if err != nil {
				return err
			}
			tx_out_proto_bytes := C.CBytes(tx_out_buf)
			defer C.free(tx_out_proto_bytes)
			tx_out_proto := &C.McBuffer{
				buffer: (*C.uint8_t)(tx_out_proto_bytes),
				len:    C.size_t(len(tx_out_buf)),
			}
			membership_proof_buf, err := proto.Marshal(r.TxOutMembershipProof)
			if err != nil {
				return err
			}
			membership_proof_proto_bytes := C.CBytes(membership_proof_buf)
			defer C.free(membership_proof_proto_bytes)
			membership_proof_proto := &C.McBuffer{
				buffer: (*C.uint8_t)(membership_proof_proto_bytes),
				len:    C.size_t(len(membership_proof_buf)),
			}
			b, err := C.mc_transaction_builder_ring_add_element(ring, tx_out_proto, membership_proof_proto)
			if err != nil {
				return err
			} else if !b {
				return errors.New("mc_transaction_builder_ring_add_element failure")
			}
		}

		var out_error *C.McError
		b, err := C.mc_transaction_builder_add_input(transaction_builder, view_private_key, subaddress_spend_private_key, C.size_t(input.RealIndex), ring, &out_error)
		if err != nil {
			return err
		} else if !b {
			if out_error == nil {
				return fmt.Errorf("mc_transaction_builder_add_input failure")
			} else {
				err = fmt.Errorf("mc_transaction_builder_add_input failed: [%d] %s", out_error.error_code, C.GoString(out_error.error_description))
				C.mc_error_free(out_error)
				return err
			}
		}
	}

	// mc_transaction_builder_add_output
	view_public_key_buf := hexToBytes(recipient.ViewPublicKey)
	view_public_key_bytes := C.CBytes(view_public_key_buf)
	defer C.free(view_public_key_bytes)
	view_public := &C.McBuffer{
		buffer: (*C.uint8_t)(view_public_key_bytes),
		len:    C.size_t(len(view_public_key_buf)),
	}

	spend_public_key_buf := hexToBytes(recipient.SpendPublicKey)
	spend_public_key_bytes := C.CBytes(spend_public_key_buf)
	defer C.free(spend_public_key_bytes)
	spend_public := &C.McBuffer{
		buffer: (*C.uint8_t)(spend_public_key_bytes),
		len:    C.size_t(len(spend_public_key_buf)),
	}

	report_url_recipient_str := C.CString(recipient.FogReportUrl)
	defer C.free(unsafe.Pointer(report_url_recipient_str))
	report_id_recipient_str := C.CString(recipient.FogReportId)
	defer C.free(unsafe.Pointer(report_id_recipient_str))
	sig_buf := hexToBytes(recipient.FogAuthoritySig)
	sig_bytes := C.CBytes(sig_buf)
	defer C.free(sig_bytes)
	authority_sig := &C.McBuffer{
		buffer: (*C.uint8_t)(sig_bytes),
		len:    C.size_t(len(sig_buf)),
	}
	fog_info := &C.McPublicAddressFogInfo{
		report_url:    (*C.char)(report_url_recipient_str),
		report_id:     (*C.char)(report_id_recipient_str),
		authority_sig: authority_sig,
	}
	recipient_address := &C.McPublicAddress{
		view_public_key:  view_public,
		spend_public_key: spend_public,
		fog_info:         fog_info,
	}

	var rRecipient ristretto.Scalar
	rRecipient.Rand()
	viewPublicKeyRecipient := hexToPoint(recipient.ViewPublicKey)
	secretRecipient := createSharedSecret(viewPublicKeyRecipient, &rRecipient)
	secret_recipient_buf := secretRecipient.Bytes()
	secret_recipient_bytes := C.CBytes(secret_recipient_buf)
	defer C.free(secret_recipient_bytes)
	out_tx_out_shared_secret := &C.McMutableBuffer{
		buffer: (*C.uint8_t)(secret_recipient_bytes),
		len:    C.size_t(len(secret_recipient_buf)),
	}
	confirmation_recipient_buf := ConfirmationNumberFromSecret(secretRecipient)
	confirmation_recipient_bytes := C.CBytes(confirmation_recipient_buf)
	defer C.free(confirmation_recipient_bytes)
	out_tx_out_confirmation_number := &C.McMutableBuffer{
		buffer: (*C.uint8_t)(confirmation_recipient_bytes),
		len:    C.size_t(len(confirmation_recipient_buf)),
	}

	var rng_callback C.McRngCallback
	var out_error *C.McError
	_, err = C.mc_transaction_builder_add_output(transaction_builder, C.uint64_t(amount), recipient_address, &rng_callback, out_tx_out_confirmation_number, out_tx_out_shared_secret, &out_error)
	if err != nil {
		return err
	}
	if out_error != nil {
		err = fmt.Errorf("mc_transaction_builder_add_output failed: [%d] %s", out_error.error_code, C.GoString(out_error.error_description))
		C.mc_error_free(out_error)
		return err
	}
	// mc_transaction_builder_add_change_output
	if changeAmount > 0 {
		view_private_key_change_buf := change.ViewPrivateKey.Bytes()
		view_private_key_change_bytes := C.CBytes(view_private_key_change_buf)
		defer C.free(view_private_key_change_bytes)
		view_private_key_change := &C.McBuffer{
			buffer: (*C.uint8_t)(view_private_key_change_bytes),
			len:    C.size_t(len(view_private_key_change_buf)),
		}
		spend_private_key_change_buf := change.SpendPrivateKey.Bytes()
		spend_private_key_change_bytes := C.CBytes(spend_private_key_change_buf)
		defer C.free(spend_private_key_change_bytes)
		spend_private_key_change := &C.McBuffer{
			buffer: (*C.uint8_t)(spend_private_key_change_bytes),
			len:    C.size_t(len(spend_private_key_change_buf)),
		}
		var fog_info_change *C.McAccountKeyFogInfo
		account_key := &C.McAccountKey{
			view_private_key:  view_private_key_change,
			spend_private_key: spend_private_key_change,
			fog_info:          fog_info_change,
		}

		spendPrivateChange := change.SubaddressSpendPrivateKey(0)
		viewPublicChange := account.PublicKey(change.SubaddressViewPrivateKey(spendPrivateChange))
		var rChange ristretto.Scalar
		rChange.Rand()
		secretChange := createSharedSecret(viewPublicChange, &rChange)
		secret_change_buf := secretChange.Bytes()
		secret_change_bytes := C.CBytes(secret_change_buf)
		defer C.free(secret_change_bytes)
		out_tx_out_shared_secret_change := &C.McMutableBuffer{
			buffer: (*C.uint8_t)(secret_change_bytes),
			len:    C.size_t(len(secret_change_buf)),
		}

		confirmation_change_buf := ConfirmationNumberFromSecret(secretChange)
		confirmation_change_key := C.CBytes(confirmation_change_buf)
		defer C.free(confirmation_change_key)
		out_tx_out_confirmation_number_change := &C.McMutableBuffer{
			buffer: (*C.uint8_t)(confirmation_change_key),
			len:    C.size_t(len(confirmation_change_buf)),
		}

		_, err = C.mc_transaction_builder_add_change_output(account_key, transaction_builder, C.uint64_t(changeAmount), &rng_callback, out_tx_out_confirmation_number_change, out_tx_out_shared_secret_change, &out_error)
		if err != nil {
			return err
		}
		if out_error != nil {
			err = fmt.Errorf("mc_transaction_builder_add_output failed: [%d] %s", out_error.error_code, C.GoString(out_error.error_description))
			C.mc_error_free(out_error)
			return err
		}
	}

	mcData, err := C.mc_transaction_builder_build(transaction_builder, &rng_callback, &out_error)
	if err != nil {
		return err
	}
	log.Println(mcData)
	return nil
}

func hexToBytes(text string) []byte {
	buf, err := hex.DecodeString(text)
	if err != nil {
		panic(err)
	}
	return buf
}
