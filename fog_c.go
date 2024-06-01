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
	"net/url"
	"strings"
	"unsafe"

	account "github.com/MixinNetwork/mobilecoin-account"
	"github.com/MixinNetwork/mobilecoin-account/types"
	"github.com/bwesterb/go-ristretto"
	"google.golang.org/protobuf/proto"
)

func ValidateAddress(recipient string) error {
	destination, err := account.DecodeB58Code(recipient)
	if err != nil {
		return err
	}
	if destination.FogReportUrl == "" {
		return nil
	}
	for _, enclave := range myenclaves {
		err = ValidateFogAddressWithEnclave(destination, enclave)
		if err != nil {
			fmt.Printf("ValidateFogAddressWithEnclave recipient: %s enclave: %s error: %v \n", recipient, enclave, err)
			continue
		}
		return nil
	}
	return fmt.Errorf("invalid recipient %s", recipient)
}

type FogFullyValidatedPubkey struct {
	// Public key in Ristretto format
	pubkey ristretto.Point

	// The pubkey_expiry value is the latest block that fog-service promises
	// that is valid to encrypt fog hints using this key for.
	// The client should obey this limit by not setting tombstone block for a
	// transaction larger than this limit if the fog pubkey is used.
	pubkey_expiry uint64
}

func ValidateFogAddressWithEnclave(recipient *account.PublicAddress, enclave string) error {
	mr_enclave_hex, err := fetchValidFogEnclave(recipient.FogReportUrl, enclave)
	if err != nil {
		return err
	}
	// Construct a verifier object that is used to verify the report's attestation
	mr_enclave_bytes, err := hex.DecodeString(mr_enclave_hex)
	if err != nil {
		return err
	}

	c_mr_enclave_bytes := C.CBytes(mr_enclave_bytes)
	defer C.free(c_mr_enclave_bytes)

	c_mr_enclave := C.McBuffer{
		buffer: (*C.uchar)(c_mr_enclave_bytes),
		len:    C.ulong(len(mr_enclave_bytes)),
	}

	mc_config_advisories, err := C.mc_advisories_create()
	if err != nil {
		return err
	}
	if mc_config_advisories == nil {
		return errors.New("mc_advisories_create failed")
	}
	defer C.mc_advisories_free(mc_config_advisories)

	mc_hardening_advisories, err := C.mc_advisories_create()
	if err != nil {
		return err
	}
	if mc_hardening_advisories == nil {
		return errors.New("mc_advisories_create failed")
	}
	defer C.mc_advisories_free(mc_hardening_advisories)

	c_advisory_id_00334 := C.CString("INTEL-SA-00334")
	defer C.free(unsafe.Pointer(c_advisory_id_00334))
	ret, err := C.mc_add_advisory(mc_hardening_advisories, c_advisory_id_00334)
	if err != nil {
		return err
	}
	if ret == false {
		return errors.New("mc_add_advisory INTEL-SA-00334 failed")
	}

	c_advisory_id_00615 := C.CString("INTEL-SA-00615")
	defer C.free(unsafe.Pointer(c_advisory_id_00615))
	ret, err = C.mc_add_advisory(mc_hardening_advisories, c_advisory_id_00615)
	if err != nil {
		return err
	}
	if ret == false {
		return errors.New("mc_add_advisory INTEL-SA-00615 failed")
	}

	c_advisory_id_00657 := C.CString("INTEL-SA-00657")
	defer C.free(unsafe.Pointer(c_advisory_id_00657))
	ret, err = C.mc_add_advisory(mc_hardening_advisories, c_advisory_id_00657)
	if err != nil {
		return err
	}
	if ret == false {
		return errors.New("mc_add_advisory INTEL-SA-00657 failed")
	}

	mc_trusted_mr_enclave_identity, err := C.mc_trusted_identity_mr_enclave_create(&c_mr_enclave, mc_config_advisories, mc_hardening_advisories)
	if err != nil {
		return err
	}
	if mc_trusted_mr_enclave_identity == nil {
		return errors.New("mc_trusted_identity_mr_enclave_create failed")
	}
	defer C.mc_trusted_identity_mr_enclave_free(mc_trusted_mr_enclave_identity)

	mc_trusted_identities, err := C.mc_trusted_identities_create()
	if err != nil {
		return err
	}
	if mc_trusted_identities == nil {
		return errors.New("mc_trusted_identities_create failed")
	}
	defer C.mc_trusted_identities_free(mc_trusted_identities)

	ret, err = C.mc_trusted_identities_add_mr_enclave(mc_trusted_identities, mc_trusted_mr_enclave_identity)
	if err != nil {
		return err
	}
	if ret == false {
		return errors.New("mc_trusted_identities_add_mr_enclave failed")
	}

	// Create the FogResolver object that is used to perform report validation using the verifier constructed above
	fog_resolver, err := C.mc_fog_resolver_create(mc_trusted_identities)
	if err != nil {
		return err
	}
	defer C.mc_fog_resolver_free(fog_resolver)

	// Connect to the fog report server and obtain a report
	report, err := GetFogReportResponse(recipient.FogReportUrl)
	if err != nil {
		return err
	}

	// Convert the report back to protobuf bytes so that it could be handed to libmobilecoin
	reportBytes, err := proto.Marshal(report)
	if err != nil {
		return err
	}

	// Add the report bytes to the resolver
	c_report_buf_bytes := C.CBytes(reportBytes)
	defer C.free(c_report_buf_bytes)

	report_buf := C.McBuffer{
		buffer: (*C.uchar)(c_report_buf_bytes),
		len:    C.ulong(len(reportBytes)),
	}

	c_address := C.CString(recipient.FogReportUrl)
	defer C.free(unsafe.Pointer(c_address))

	// Used for returning errors from libmobilecoin
	var mc_error *C.McError
	ret, err = C.mc_fog_resolver_add_report_response(
		fog_resolver,
		c_address,
		&report_buf,
		&mc_error,
	)
	if err != nil {
		return err
	}
	if ret == false {
		if mc_error == nil {
			return errors.New("mc_fog_resolver_add_report_response failed")
		} else {
			err = fmt.Errorf("mc_fog_resolver_add_report_response failed: [%d] %s", mc_error.error_code, C.GoString(mc_error.error_description))
			C.mc_error_free(mc_error)
			return err
		}
	}

	// Convert recipient from the Go representation to protobuf bytes
	protobufRecipient, err := PublicAddressToProtobuf(recipient)
	if err != nil {
		return err
	}

	recipientProtobufBytes, err := proto.Marshal(protobufRecipient)
	if err != nil {
		return err
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
		return err
	}
	if fully_validated_fog_pub_key == nil {
		if mc_error == nil {
			return errors.New("get_fog_pubkey failed: no error returned?!")
		} else {
			err = fmt.Errorf("get_fog_pubkey failed: [%d] %s", mc_error.error_code, C.GoString(mc_error.error_description))
			C.mc_error_free(mc_error)
			return err
		}
	}
	defer C.mc_fully_validated_fog_pubkey_free(fully_validated_fog_pub_key)

	// Get the pubkey expiry
	_, err = C.mc_fully_validated_fog_pubkey_get_pubkey_expiry(fully_validated_fog_pub_key)
	if err != nil {
		return err
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
		return err
	}
	fog_pubkey_bytes := C.GoBytes(out_buf, 32)

	// Convert pubkey bytes to ristretto Point
	var fog_pubkey ristretto.Point
	err = fog_pubkey.UnmarshalBinary(fog_pubkey_bytes)
	if err != nil {
		return err
	}

	return nil
}

// Utility method to convert the internal Go PublicAddress to the external GRPC object
func PublicAddressToProtobuf(addr *account.PublicAddress) (*types.PublicAddress, error) {
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

	protobufObject := &types.PublicAddress{
		ViewPublicKey:   &types.CompressedRistretto{Data: view},
		SpendPublicKey:  &types.CompressedRistretto{Data: spend},
		FogReportUrl:    addr.FogReportUrl,
		FogReportId:     addr.FogReportId,
		FogAuthoritySig: fog_authority_sig,
	}

	return protobufObject, nil
}

func fetchValidFogEnclave(host, enclave string) (string, error) {
	fog_url_to_mr_enclave_hex := map[string]string{
		"fog://fog.prod.mobilecoinww.com":            enclave,
		"fog://service.fog.mob.production.namda.net": enclave,
		"fog://fog-rpt-prd.namda.net":                enclave,
		// "fog://fog.test.mobilecoin.com":              enclave,
		// "fog://service.fog.mob.staging.namda.net":    "a4764346f91979b4906d4ce26102228efe3aba39216dec1e7d22e6b06f919f11",
	}

	uri, err := url.Parse(host)
	if err != nil {
		return "", err
	}
	if uri.Port() != "" {
		host = strings.ReplaceAll(host, ":"+uri.Port(), "")
	}
	mr_enclave_hex, ok := fog_url_to_mr_enclave_hex[host]
	if !ok {
		return "", errors.New("No enclave hex for Address' fog url")
	}
	return mr_enclave_hex, nil
}
