package api

import (
	"testing"
    "fmt"
	"github.com/stretchr/testify/assert"
)




func TestFog(t *testing.T) {
	assert := assert.New(t)
	hint, err := fakeOnetimeHint()
	assert.Equal(err, nil)
	assert.Equal(EncryptedFogHintSize, len(hint))

    pub_addr := PublicAddress {
        ViewPublicKey: "c07d10b8386a2a0b39a0ca0e434c2ec95d3d991c616a476d8d0ab0a1ef9a0828",
        SpendPublicKey: "b24518042d0ce9da90f59d58c3d7e1c5db0395dbaa57ce9dcd55cd49550a4b35",
        FogReportUrl: "fog://service.fog.mob.staging.namda.net",
        FogReportId: "",
        FogAuthoritySig: "a62ed408544a985cde62c15cd5f8b7fa0c922d249be79063dc980e0f308a1c1362b9bc80656e2db17579dafe72a98971156bf159e6e1e95451e732cd12f3fe8c",
    }


    reportResp, err := GetFogPubkeyRust(&pub_addr)
	assert.Equal(err, nil)
    fmt.Printf("repoirt %#v", reportResp)
}
