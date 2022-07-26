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
	"errors"
	"fmt"
)

// mc_transaction_builder_create
func MCTransactionBuilderCreate(inputCs []*InputC, fee, tombstone uint64, version uint32) error {
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
}
