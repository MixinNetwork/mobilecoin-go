package api

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/url"
	"unsafe"

	"github.com/MixinNetwork/mobilecoin-go/block"
	"github.com/bwesterb/go-ristretto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

// #include <stdio.h>
// #include <stdlib.h>
// #include <errno.h>
// #include "libmobilecoin.h"
// #cgo CFLAGS: -I./include
// #cgo LDFLAGS: ./include/libmobilecoin.a -framework Security -framework Foundation
import "C"

const (
	MAJOR_VERSION        = 1
	LATEST_MINOR_VERSION = 0

	EncryptedFogHintSize = 84
	FooterSize           = 50
)

// generate an EncryptedFogHint
func fakeOnetimeHint() ([]byte, error) {
	plaintext := make([]byte, EncryptedFogHintSize-FooterSize)
	var key ristretto.Point
	key.Rand()
	return encryptFixedLength(&key, plaintext)
}

// https://github.com/mobilecoinfoundation/mobilecoin/blob/9f3191d7c3027385b72863cea74e1fdab0525130/transaction/std/src/transaction_builder.rs#L402
// create_fog_hint
func CreateFogHint(recipient *PublicAddress) ([]byte, uint64, error) {
	// fog_report_url is none
	if len(recipient.FogReportUrl) == 0 {
		hint, err := fakeOnetimeHint()
		if err != nil {
			return nil, 0, err
		}
		return hint, math.MaxUint64, nil
	}

	pubkey, err := GetFogPubkeyRust(recipient)
	if err != nil {
		return nil, 0, err
	}

	return pubkey.pubkey_bytes, pubkey.pubkey_expiry, nil
}

func GetFogReportResponse(address string) (*block.ReportResponse, error) {
	uri, err := url.Parse(address)
	if err != nil {
		return nil, err
	}

	// Use system RootCAs
	creds := credentials.NewTLS(&tls.Config{})

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(creds))
	conn, err := grpc.Dial(fmt.Sprintf("%s:443", uri.Host), opts...)
	if err != nil {
		return nil, err
	}

	defer conn.Close()
	client := block.NewReportAPIClient(conn)

	in := &block.ReportRequest{}
	return client.GetReports(context.Background(), in)
}

// A fully validated Fog Pubkey used to encrypt hints.
// This mimics https://github.com/mobilecoinfoundation/mobilecoin/blob/master/fog/report/validation/src/traits.rs#L29
type FogFullyValidatedPubkey struct {
	// Public key in Ristretto format
	pubkey ristretto.Point

	// Public key in 32 bytes array
	pubkey_bytes []byte

	// The pubkey_expiry value is the latest block that fog-service promises
	// that is valid to encrypt fog hints using this key for.
	// The client should obey this limit by not setting tombstone block for a
	// transaction larger than this limit if the fog pubkey is used.
	pubkey_expiry uint64
}

// Utility method to convert the internal Go PublicAddress to the external GRPC object
func PublicAddressToProtobuf(addr *PublicAddress) (*block.PublicAddress, error) {
	view, err := hex.DecodeString(addr.ViewPublicKey)
	if err != nil {
		return nil, err
	}
	spend, err := hex.DecodeString(addr.SpendPublicKey)
	if err != nil {
		return nil, err
	}
	fog_authority_sig, err := hex.DecodeString(addr.FogAuthoritySig)
	if err != nil {
		return nil, err
	}

	protobufObject := &block.PublicAddress{
		ViewPublicKey:   &block.CompressedRistretto{Data: view},
		SpendPublicKey:  &block.CompressedRistretto{Data: spend},
		FogReportUrl:    addr.FogReportUrl,
		FogReportId:     addr.FogReportId,
		FogAuthoritySig: fog_authority_sig,
	}

	return protobufObject, nil
}

// A function that gets a MobileCoin public address, contacts the fog report server
// associated with it to get a report, and if successful returns the fully validated fog key.
// Note: Assumes the address is a Fog address. Do not use if FogReportUrl is empty.
func GetFogPubkeyRust(recipient *PublicAddress) (*FogFullyValidatedPubkey, error) {
	if recipient.FogReportUrl == "" {
		return nil, errors.New("Not a fog address")
	}

	fmt.Printf("\n-------------------------------------------\n")
	fmt.Printf("------RECIPIENT ADDRESS FOG REPORT URL-----\n")
	fmt.Printf("-------------------------------------------\n")
	fmt.Printf(recipient.FogReportUrl)
	fmt.Printf("\n-------------------------------------------\n")

	// Convert recipient from the Go representation to protobuf bytes
	protobufRecipient, err := PublicAddressToProtobuf(recipient)
	if err != nil {
		return nil, err
	}

	recipientProtobufBytes, err := proto.Marshal(protobufRecipient)
	if err != nil {
		return nil, err
	}

	// Used for returning errors from libmobilecoin
	var mc_error *C.McError

	// Connect to the fog report server and obtain a report
	report, err := GetFogReportResponse(recipient.FogReportUrl)
	if err != nil {
		return nil, err
	}

	// Convert the report back to protobuf bytes so that it could be handed to libmobilecoin
	reportBytes, err := proto.Marshal(report)
	if err != nil {
		return nil, err
	}

	fog_url_to_mr_enclave_hex := map[string]string{
		"fog://fog.prod.mobilecoinww.com":            "f3f7e9a674c55fb2af543513527b6a7872de305bac171783f6716a0bf6919499",
		"fog://service.fog.mob.production.namda.net": "f3f7e9a674c55fb2af543513527b6a7872de305bac171783f6716a0bf6919499",
		"fog://service.fog.mob.staging.namda.net":    "a4764346f91979b4906d4ce26102228efe3aba39216dec1e7d22e6b06f919f11",
	}

	mr_enclave_hex, ok := fog_url_to_mr_enclave_hex[string(recipient.FogReportUrl)]
	if !ok {
		return nil, errors.New("No enclave hex for Address' fog url")
	}

	// Construct a verifier object that is used to verify the report's attestation
	mr_enclave_bytes, err := hex.DecodeString(mr_enclave_hex)
	if err != nil {
		return nil, err
	}

	c_mr_enclave_bytes := C.CBytes(mr_enclave_bytes)
	defer C.free(c_mr_enclave_bytes)

	c_mr_enclave := C.McBuffer{
		buffer: (*C.uchar)(c_mr_enclave_bytes),
		len:    C.ulong(len(mr_enclave_bytes)),
	}

	mr_enclave_verifier, err := C.mc_mr_enclave_verifier_create(&c_mr_enclave)
	if err != nil {
		return nil, err
	}
	if mr_enclave_verifier == nil {
		return nil, errors.New("mc_mr_enclave_verifier_create failed")
	}
	defer C.mc_mr_enclave_verifier_free(mr_enclave_verifier)

	c_advisory_id := C.CString("INTEL-SA-00334")
	defer C.free(unsafe.Pointer(c_advisory_id))
	ret, err := C.mc_mr_enclave_verifier_allow_hardening_advisory(mr_enclave_verifier, c_advisory_id)
	if err != nil {
		return nil, err
	}
	if ret == false {
		return nil, errors.New("mc_mr_enclave_verifier_allow_hardening_advisory failed")
	}

	verifier, err := C.mc_verifier_create()
	if err != nil {
		return nil, err
	}
	defer C.mc_verifier_free(verifier)

	ret, err = C.mc_verifier_add_mr_enclave(verifier, mr_enclave_verifier)
	if err != nil {
		return nil, err
	}
	if ret == false {
		return nil, errors.New("mc_verifier_add_mr_enclave failed")
	}

	// Create the FogResolver object that is used to perform report validation using the verifier constructed above
	fog_resolver, err := C.mc_fog_resolver_create(verifier)
	if err != nil {
		return nil, err
	}
	defer C.mc_fog_resolver_free(fog_resolver)

	// Add the report bytes to the resolver
	c_report_buf_bytes := C.CBytes(reportBytes)
	defer C.free(c_report_buf_bytes)

	report_buf := C.McBuffer{
		buffer: (*C.uchar)(c_report_buf_bytes),
		len:    C.ulong(len(reportBytes)),
	}

	c_address := C.CString(recipient.FogReportUrl)
	defer C.free(unsafe.Pointer(c_address))

	ret, err = C.mc_fog_resolver_add_report_response(
		fog_resolver,
		c_address,
		&report_buf,
		&mc_error,
	)
	if err != nil {
		return nil, err
	}
	if ret == false {
		if mc_error == nil {
			return nil, errors.New("mc_fog_resolver_add_report_response failed")
		} else {
			err = fmt.Errorf("mc_fog_resolver_add_report_response failed: [%d] %s", mc_error.error_code, C.GoString(mc_error.error_description))
			C.mc_error_free(mc_error)
			return nil, err
		}
	}

	// Perform the actual validation and key extraction
	c_recipient_bytes := C.CBytes(recipientProtobufBytes)
	defer C.free(c_recipient_bytes)

	c_recipient_buf := C.McBuffer{
		buffer: (*C.uchar)(c_recipient_bytes),
		len:    (C.ulong)(len(recipientProtobufBytes)),
	}
	fully_validated_fog_pub_key, err := C.mc_fog_resolver_get_fog_pubkey_from_protobuf_public_address(
		fog_resolver,
		&c_recipient_buf,
		&mc_error,
	)
	if err != nil {
		return nil, err
	}
	if fully_validated_fog_pub_key == nil {
		if mc_error == nil {
			return nil, errors.New("get_fog_pubkey failed: no error returned?!")
		} else {
			err = fmt.Errorf("get_fog_pubkey failed: [%d] %s", mc_error.error_code, C.GoString(mc_error.error_description))
			C.mc_error_free(mc_error)
			return nil, err
		}
	}
	defer C.mc_fully_validated_fog_pubkey_free(fully_validated_fog_pub_key)

	// Get the pubkey expiry
	pubkey_expiry, err := C.mc_fully_validated_fog_pubkey_get_pubkey_expiry(fully_validated_fog_pub_key)
	if err != nil {
		return nil, err
	}

	// Get the pubkey
	out_buf := C.malloc(32)
	defer C.free(out_buf)

	mutable_buf := (*C.McMutableBuffer)(C.malloc(C.sizeof_McMutableBuffer))
	defer C.free(unsafe.Pointer(mutable_buf))
	mutable_buf.buffer = (*C.uchar)(out_buf)
	mutable_buf.len = 32

	_, err = C.mc_fully_validated_fog_pubkey_get_pubkey(fully_validated_fog_pub_key, mutable_buf)
	if err != nil {
		return nil, err
	}
	fog_pubkey_bytes := C.GoBytes(out_buf, 32)

	// Convert pubkey bytes to ristretto Point
	var fog_pubkey ristretto.Point
	err = fog_pubkey.UnmarshalBinary(fog_pubkey_bytes)
	if err != nil {
		return nil, err
	}

	// Return successful result
	return &FogFullyValidatedPubkey{
		pubkey:        fog_pubkey,
		pubkey_bytes:  fog_pubkey_bytes,
		pubkey_expiry: uint64(pubkey_expiry),
	}, nil
}
