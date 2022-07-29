package api

import (
	"encoding/hex"
	"errors"

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

func MCAccountKeyGetSubAddressPrivateKeys(viewPrivateKeyStr, spendPrivateKeyStr string, index uint) (string, string, error) {
	viewPrivateKey := account.HexToScalar(viewPrivateKeyStr)
	view_private_key_buf := viewPrivateKey.Bytes()
	view_private_key_bytes := C.CBytes(view_private_key_buf)
	defer C.free(view_private_key_bytes)
	view_private_key := &C.McBuffer{
		buffer: (*C.uint8_t)(view_private_key_bytes),
		len:    C.size_t(len(view_private_key_buf)),
	}

	spendPrivateKey := account.HexToScalar(spendPrivateKeyStr)
	spend_private_key_buf := spendPrivateKey.Bytes()
	spend_private_key_bytes := C.CBytes(spend_private_key_buf)
	defer C.free(spend_private_key_bytes)
	spend_private_key := &C.McBuffer{
		buffer: (*C.uint8_t)(spend_private_key_bytes),
		len:    C.size_t(len(spend_private_key_buf)),
	}

	out_subaddress_view_private_buf := make([]byte, 32)
	out_subaddress_view_private_bytes := C.CBytes(out_subaddress_view_private_buf)
	defer C.free(out_subaddress_view_private_bytes)
	out_subaddress_view_private := &C.McMutableBuffer{
		buffer: (*C.uint8_t)(out_subaddress_view_private_bytes),
		len:    C.size_t(len(out_subaddress_view_private_buf)),
	}

	out_subaddress_spend_private_buf := make([]byte, 32)
	out_subaddress_spend_private_bytes := C.CBytes(out_subaddress_spend_private_buf)
	defer C.free(out_subaddress_spend_private_bytes)
	out_subaddress_spend_private := &C.McMutableBuffer{
		buffer: (*C.uint8_t)(out_subaddress_spend_private_bytes),
		len:    C.size_t(len(out_subaddress_spend_private_buf)),
	}

	b, err := C.mc_account_key_get_subaddress_private_keys(view_private_key, spend_private_key, C.uint64_t(index), out_subaddress_view_private, out_subaddress_spend_private)
	if err != nil {
		return "", "", err
	}
	if !b {
		return "", "", errors.New("invalid private key")
	}

	return hex.EncodeToString(C.GoBytes(out_subaddress_view_private_bytes, 32)), hex.EncodeToString(C.GoBytes(out_subaddress_spend_private_bytes, 32)), nil
}
