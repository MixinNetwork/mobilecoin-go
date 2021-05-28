package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"fmt"
	"math"
	"net/url"

	"github.com/MixinNetwork/mobilecoin-go/block"
	"github.com/bwesterb/go-ristretto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

//go:embed credentials/8395.crt
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
