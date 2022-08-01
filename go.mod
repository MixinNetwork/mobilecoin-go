module github.com/MixinNetwork/mobilecoin-go

go 1.18

replace github.com/jadeydi/mobilecoin-account => ../mobilecoin-account

require (
	github.com/ChainSafe/go-schnorrkel v0.0.0-20210318173838-ccb5cd955283
	github.com/MixinNetwork/go-number v0.0.0-20210414133019-df3477b564b8
	github.com/bwesterb/go-ristretto v1.2.1
	github.com/dchest/blake2b v1.0.0
	github.com/gtank/merlin v0.1.1
	github.com/jadeydi/mobilecoin-account v1.2.3
	github.com/stretchr/testify v1.7.0
	golang.org/x/crypto v0.0.0-20211108221036-ceb1ce70b4fa
	google.golang.org/grpc v1.48.0
	google.golang.org/protobuf v1.28.1
)

require (
	github.com/btcsuite/btcutil v1.0.2 // indirect
	github.com/cosmos/go-bip39 v1.0.0 // indirect
	github.com/davecgh/go-spew v1.1.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/gtank/ristretto255 v0.1.2 // indirect
	github.com/mimoo/StrobeGo v0.0.0-20210601165009-122bf33a46e0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/shopspring/decimal v1.2.1-0.20210329231237-501661573f60 // indirect
	golang.org/x/net v0.0.0-20220728153142-1f511ac62c11 // indirect
	golang.org/x/sys v0.0.0-20220728004956-3c1f35247d10 // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/genproto v0.0.0-20220725144611-272f38e5d71b // indirect
	gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c // indirect
)
