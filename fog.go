package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"

	"github.com/MixinNetwork/mobilecoin-account/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func GetFogReportResponse(address string) (*types.ReportResponse, error) {
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
	client := types.NewReportAPIClient(conn)

	in := &types.ReportRequest{}
	return client.GetReports(context.Background(), in)
}
