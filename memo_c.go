package api

import (
	"encoding/hex"
	"fmt"
	"unsafe"

	account "github.com/MixinNetwork/mobilecoin-account"
)

// #cgo CFLAGS: -I${SRCDIR}/include
// #cgo darwin LDFLAGS: ${SRCDIR}/include/libmobilecoin.a -framework Security -framework Foundation
// #cgo linux LDFLAGS: ${SRCDIR}/include/libmobilecoin_linux.a -lm -ldl
// #include <stdio.h>
// #include <stdlib.h>
// #include <errno.h>
// #include "libmobilecoin.h"
import "C"

// mc_memo_decrypt_e_memo_payload
func DecryptEMemoPayload(encryptedMemoStr, txOutPublicKey, viewPrivateKeyStr, spendPrivateKeyStr string) (string, error) {
	encrypted_memo_buf := account.HexToBytes(encryptedMemoStr)
	encrypted_memo_bytes := C.CBytes(encrypted_memo_buf)
	defer C.free(encrypted_memo_bytes)
	encrypted_memo := &C.McBuffer{
		buffer: (*C.uint8_t)(encrypted_memo_bytes),
		len:    C.size_t(len(encrypted_memo_buf)),
	}

	publicKey := account.HexToPoint(txOutPublicKey)
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

	spendPrivateKey := account.HexToScalar(spendPrivateKeyStr)
	spend_private_key_buf := spendPrivateKey.Bytes()
	spend_private_key_bytes := C.CBytes(spend_private_key_buf)
	defer C.free(spend_private_key_bytes)
	spend_private_key := &C.McBuffer{
		buffer: (*C.uint8_t)(spend_private_key_bytes),
		len:    C.size_t(len(spend_private_key_buf)),
	}
	var fog_info *C.McAccountKeyFogInfo
	account_key := (*C.McAccountKey)(C.malloc(C.sizeof_McAccountKey))
	defer C.free(unsafe.Pointer(account_key))
	account_key.view_private_key = view_private_key
	account_key.spend_private_key = spend_private_key
	account_key.fog_info = fog_info

	out_memo_buf := make([]byte, 66)
	out_memo_bytes := C.CBytes(out_memo_buf)
	defer C.free(out_memo_bytes)
	out_memo_payload := &C.McMutableBuffer{
		buffer: (*C.uint8_t)(out_memo_bytes),
		len:    C.size_t(len(out_memo_buf)),
	}

	var out_error *C.McError
	b, err := C.mc_memo_decrypt_e_memo_payload(encrypted_memo, tx_out_public_key, view_private_key, out_memo_payload, &out_error)
	if err != nil {
		return "", err
	}
	if !b && out_error != nil {
		err = fmt.Errorf("mc_memo_decrypt_e_memo_payload failed: [%d] %s", out_error.error_code, C.GoString(out_error.error_description))
		C.mc_error_free(out_error)
		return "", err
	}

	return hex.EncodeToString(C.GoBytes(out_memo_bytes, 66)), nil
}
