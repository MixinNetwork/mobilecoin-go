module github.com/MixinNetwork/mobilecoin-go

go 1.16

replace github.com/jadeydi/mobilecoin-account => ../mobilecoin-account

require (
	github.com/ChainSafe/go-schnorrkel v0.0.0-20210318173838-ccb5cd955283
	github.com/MixinNetwork/go-number v0.0.0-20210414133019-df3477b564b8 // indirect
	github.com/bwesterb/go-ristretto v1.2.1
	github.com/cosmos/go-bip39 v1.0.0 // indirect
	github.com/dchest/blake2b v1.0.0
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/gtank/merlin v0.1.1
	github.com/jadeydi/mobilecoin-account v1.2.1
	github.com/mimoo/StrobeGo v0.0.0-20210601165009-122bf33a46e0 // indirect
	github.com/stretchr/testify v1.7.0
	golang.org/x/crypto v0.0.0-20211108221036-ceb1ce70b4fa
	google.golang.org/grpc v1.48.0
	google.golang.org/protobuf v1.28.1
)
