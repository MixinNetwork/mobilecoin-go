package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"fmt"
	"math"
	"net/url"
    "unsafe"
    "encoding/hex"

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
// #cgo CFLAGS: -I/Users/eran/Projects/mc/mobilecoin/libmobilecoin/include
// #cgo LDFLAGS: /Users/eran/Projects/mc/mobilecoin/target/debug/libmobilecoin.a -framework Security -framework Foundation
import "C"



//go:embed credentials/lets-encrypt.crt
var crt []byte

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

func CreateFogHint(recipient *block.PublicAddress) ([]byte, uint64, error) {
	// fog_report_url is none
	if len(recipient.FogReportUrl) == 0 {
		hint, err := fakeOnetimeHint()
		if err != nil {
			return nil, 0, err
		}
		return hint, math.MaxUint64, nil
	}

	// validated_fog_pubkey := GetFogPubkey(recipient)

	return nil, 0, nil
}

func FakeFogHint(recipient *PublicAddress) ([]byte, uint64, error) {
	return nil, 0, nil
}

func GetFogReportResponse(address string) (*block.ReportResponse, error) {
	uri, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(crt) {
		return nil, fmt.Errorf("credentials: failed to append certificates")
	}
	creds := credentials.NewTLS(&tls.Config{RootCAs: cp})

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


func GetFogPubkeyRust(recipient *PublicAddress) (*ristretto.Point, error) { // TODO need to also return pubkey expiry
    report, err := GetFogReportResponse(recipient.FogReportUrl)
    if err != nil {
        return nil, err
    }
    reportBytes, err := proto.Marshal(report)
    if err != nil {
        return nil, err
    }

    fmt.Printf("report bytes %#v\n", len(reportBytes))

    verifier, err := C.mc_verifier_create();
    if err != nil {
        return nil, err
    }
    fmt.Printf("verifier: %#v\n", verifier)

    fog_resolver, err := C.mc_fog_resolver_create(verifier)
    if err != nil {
        return nil, err
    }
    fmt.Printf("fog_resolver: %#v\n", fog_resolver)

    c_report_buf := C.CBytes(reportBytes)
    defer C.free(c_report_buf)

    report_buf := C.McBuffer { buffer: (*C.uchar)(c_report_buf), len: C.ulong(len(reportBytes)) }
    fmt.Printf("report bytes %#v eheh\n", report_buf)

    c_address := C.CString(recipient.FogReportUrl)
	defer C.free(unsafe.Pointer(c_address))


    ret, err := C.mc_fog_resolver_add_report_response(
        fog_resolver,
        c_address,
        &report_buf,
        nil,
    )
    if err != nil {
        return nil, err
    }
    fmt.Printf("add report: %#v\n", ret)




    // Go PublicAddress to libmobilecoin
    view_bytes, err := hex.DecodeString(recipient.ViewPublicKey)
    if err != nil { return nil, err }
    c_view_bytes := C.CBytes(view_bytes)
    defer C.free(c_view_bytes)

    spend_bytes, err := hex.DecodeString(recipient.SpendPublicKey)
    if err != nil { return nil, err }
    c_spend_bytes := C.CBytes(spend_bytes)
    defer C.free(c_spend_bytes)

    authority_sig_bytes, err := hex.DecodeString(recipient.FogAuthoritySig)
    if err != nil { return nil, err }
    c_authority_sig_bytes := C.CBytes(authority_sig_bytes)
    defer C.free(c_authority_sig_bytes)

    c_report_url := C.CString(recipient.FogReportUrl)
    defer C.free(unsafe.Pointer(c_report_url))

    c_report_id := C.CString(recipient.FogReportId)
    defer C.free(unsafe.Pointer(c_report_id))

    c_authority_sig := (*C.McBuffer)(C.malloc(C.sizeof_McBuffer))
    defer C.free(unsafe.Pointer(c_authority_sig))
    c_authority_sig.buffer = (*C.uchar)(c_authority_sig_bytes)
    c_authority_sig.len = C.ulong(len(authority_sig_bytes))

    c_fog_info := (*C.McPublicAddressFogInfo)(C.malloc(C.sizeof_McPublicAddressFogInfo))
    defer C.free(unsafe.Pointer(c_fog_info))
    c_fog_info.report_url = c_report_url
    c_fog_info.report_id = c_report_id
    c_fog_info.authority_sig = c_authority_sig

    c_view_public_key := (*C.McBuffer)(C.malloc(C.sizeof_McBuffer))
    defer C.free(unsafe.Pointer(c_view_public_key))
    c_view_public_key.buffer = (*C.uchar)(c_view_bytes)
    c_view_public_key.len = C.ulong(len(view_bytes))

    c_spend_public_key := (*C.McBuffer)(C.malloc(C.sizeof_McBuffer))
    defer C.free(unsafe.Pointer(c_spend_public_key))
    c_spend_public_key.buffer = (*C.uchar)(c_spend_bytes)
    c_spend_public_key.len = C.ulong(len(spend_bytes))

    c_public_address := (*C.McPublicAddress)(C.malloc(C.sizeof_McPublicAddress))
    defer C.free(unsafe.Pointer(c_public_address))
    c_public_address.view_public_key = c_view_public_key
    c_public_address.spend_public_key = c_spend_public_key
    c_public_address.fog_info = c_fog_info

    fully_validated_fog_pub_key, err := C.mc_fog_resolver_get_fog_pubkey(
        fog_resolver,
        c_public_address,
    )
    if err != nil { return nil, err }

    fmt.Printf("fully validated fog pub key: %#v\n", fully_validated_fog_pub_key)

    return nil, nil
}
