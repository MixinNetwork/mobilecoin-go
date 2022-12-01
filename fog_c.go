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
			fmt.Printf("ValidateFogAddressWithEnclave error: %v \n", err)
			continue
		}
	}
	return err
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
	// Used for returning errors from libmobilecoin
	var mc_error *C.McError
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

	fog_url_to_mr_enclave_hex := fetchValidFogURL(enclave)

	uri, err := url.Parse(recipient.FogReportUrl)
	if err != nil {
		return err
	}

	host := recipient.FogReportUrl
	if uri.Port() != "" {
		host = strings.ReplaceAll(host, ":"+uri.Port(), "")
	}
	mr_enclave_hex, ok := fog_url_to_mr_enclave_hex[host]
	if !ok {
		return errors.New("No enclave hex for Address' fog url")
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

	mr_enclave_verifier, err := C.mc_mr_enclave_verifier_create(&c_mr_enclave)
	if err != nil {
		return err
	}
	if mr_enclave_verifier == nil {
		return errors.New("mc_mr_enclave_verifier_create failed")
	}
	defer C.mc_mr_enclave_verifier_free(mr_enclave_verifier)

	c_advisory_id := C.CString("INTEL-SA-00334")
	defer C.free(unsafe.Pointer(c_advisory_id))
	ret, err := C.mc_mr_enclave_verifier_allow_hardening_advisory(mr_enclave_verifier, c_advisory_id)
	if err != nil {
		return err
	}
	if ret == false {
		return errors.New("mc_mr_enclave_verifier_allow_hardening_advisory INTEL-SA-00334 failed")
	}

	c_advisory_id_00615 := C.CString("INTEL-SA-00615")
	defer C.free(unsafe.Pointer(c_advisory_id_00615))
	ret, err = C.mc_mr_enclave_verifier_allow_hardening_advisory(mr_enclave_verifier, c_advisory_id_00615)
	if err != nil {
		return err
	}
	if ret == false {
		return errors.New("mc_mr_enclave_verifier_allow_hardening_advisory INTEL-SA-00615 failed")
	}

	c_advisory_id_00657 := C.CString("INTEL-SA-00657")
	defer C.free(unsafe.Pointer(c_advisory_id_00657))
	ret, err = C.mc_mr_enclave_verifier_allow_hardening_advisory(mr_enclave_verifier, c_advisory_id_00657)
	if err != nil {
		return err
	}
	if ret == false {
		return errors.New("mc_mr_enclave_verifier_allow_hardening_advisory INTEL-SA-00657 failed")
	}

	verifier, err := C.mc_verifier_create()
	if err != nil {
		return err
	}
	defer C.mc_verifier_free(verifier)

	ret, err = C.mc_verifier_add_mr_enclave(verifier, mr_enclave_verifier)
	if err != nil {
		return err
	}
	if ret == false {
		return errors.New("mc_verifier_add_mr_enclave failed")
	}

	// Create the FogResolver object that is used to perform report validation using the verifier constructed above
	fog_resolver, err := C.mc_fog_resolver_create(verifier)
	if err != nil {
		return err
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

func fetchValidFogURL(enclave string) map[string]string {
	return map[string]string{
		"fog://fog.prod.mobilecoinww.com":            enclave,
		"fog://service.fog.mob.production.namda.net": enclave,
		"fog://fog-rpt-prd.namda.net":                enclave,
		// "fog://service.fog.mob.staging.namda.net":    "a4764346f91979b4906d4ce26102228efe3aba39216dec1e7d22e6b06f919f11",
	}
}
