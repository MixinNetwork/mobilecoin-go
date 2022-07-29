package api

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"unsafe"

	account "github.com/jadeydi/mobilecoin-account"
)

// #cgo CFLAGS: -I${SRCDIR}/include
// #cgo darwin LDFLAGS: ${SRCDIR}/include/libmobilecoin.a -framework Security -framework Foundation
// #cgo linux LDFLAGS: ${SRCDIR}/include/libmobilecoin_linux.a -lm -ldl -lz
// #include <stdio.h>
// #include <stdlib.h>
// #include <errno.h>
// #include "libmobilecoin.h"
import "C"

type TxOutAmount struct {
	Value   uint64
	TokenID uint64
}

func MCTxOutGetAmount(maskedAmountStr, maskedTokenIDStr, publicKeyStr, viewPrivateKeyStr string) (*TxOutAmount, error) {
	masked_amount, err := strconv.ParseUint(maskedAmountStr, 10, 64)
	if err != nil {
		return nil, err
	}
	masked_token_id_buf := account.HexToBytes(maskedTokenIDStr)
	masked_token_id_bytes := C.CBytes(masked_token_id_buf)
	defer C.free(masked_token_id_bytes)
	masked_token_id := &C.McBuffer{
		buffer: (*C.uint8_t)(masked_token_id_bytes),
		len:    C.size_t(len(masked_token_id_buf)),
	}
	tx_out_masked_amount := (*C.McTxOutMaskedAmount)(C.malloc(C.sizeof_McTxOutMaskedAmount))
	defer C.free(unsafe.Pointer(tx_out_masked_amount))
	tx_out_masked_amount.masked_value = C.uint64_t(masked_amount)
	tx_out_masked_amount.masked_token_id = masked_token_id

	publicKey := account.HexToPoint(publicKeyStr)
	public_key_buf := publicKey.Bytes()
	public_key_bytes := C.CBytes(public_key_buf)
	defer C.free(public_key_bytes)
	tx_out_public_key := &C.McBuffer{
		buffer: (*C.uint8_t)(public_key_bytes),
		len:    C.size_t(len(public_key_buf)),
	}
	viewPrivateKey := account.HexToScalar(viewPrivateKeyStr)
	view_private_key_buf := viewPrivateKey.Bytes()
	view_private_key_bytes := C.CBytes(view_private_key_buf)
	defer C.free(view_private_key_bytes)
	view_private_key := &C.McBuffer{
		buffer: (*C.uint8_t)(view_private_key_bytes),
		len:    C.size_t(len(view_private_key_buf)),
	}

	out_amount := &C.McTxOutAmount{
		value:    C.uint64_t(0),
		token_id: C.uint64_t(0),
	}
	var out_error *C.McError
	b, err := C.mc_tx_out_get_amount(tx_out_masked_amount, tx_out_public_key, view_private_key, out_amount, &out_error)
	if err != nil {
		return nil, err
	}
	if !b && out_error != nil {
		err = fmt.Errorf("mc_tx_out_get_amount failed: [%d] %s", out_error.error_code, C.GoString(out_error.error_description))
		C.mc_error_free(out_error)
		return nil, err
	}
	return &TxOutAmount{
		Value:   uint64(out_amount.value),
		TokenID: uint64(out_amount.token_id),
	}, nil
}

func McTxOutGetSharedSecret(publicKeyStr, viewPrivateKeyStr string) (string, error) {
	publicKey := account.HexToPoint(publicKeyStr)
	public_key_buf := publicKey.Bytes()
	public_key_bytes := C.CBytes(public_key_buf)
	defer C.free(public_key_bytes)
	tx_out_public_key := &C.McBuffer{
		buffer: (*C.uint8_t)(public_key_bytes),
		len:    C.size_t(len(public_key_buf)),
	}
	viewPrivateKey := account.HexToScalar(viewPrivateKeyStr)
	view_private_key_buf := viewPrivateKey.Bytes()
	view_private_key_bytes := C.CBytes(view_private_key_buf)
	defer C.free(view_private_key_bytes)
	view_private_key := &C.McBuffer{
		buffer: (*C.uint8_t)(view_private_key_bytes),
		len:    C.size_t(len(view_private_key_buf)),
	}

	out_shared_secret_buf := make([]byte, 32)
	out_shared_secret_bytes := C.CBytes(out_shared_secret_buf)
	defer C.free(out_shared_secret_bytes)
	out_shared_secret := &C.McMutableBuffer{
		buffer: (*C.uint8_t)(out_shared_secret_bytes),
		len:    C.size_t(len(out_shared_secret_buf)),
	}

	var out_error *C.McError
	b, err := C.mc_tx_out_get_shared_secret(view_private_key, tx_out_public_key, out_shared_secret, &out_error)
	if err != nil {
		return "", err
	}
	if !b && out_error != nil {
		err = fmt.Errorf("mc_tx_out_get_shared_secret failed: [%d] %s", out_error.error_code, C.GoString(out_error.error_description))
		C.mc_error_free(out_error)
		return "", err
	}
	return hex.EncodeToString(C.GoBytes(out_shared_secret_bytes, 32)), nil
}
