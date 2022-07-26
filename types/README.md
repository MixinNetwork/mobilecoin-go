Generate go files from protos
protoc -I=./protos --go_out=. ./protos/external.proto