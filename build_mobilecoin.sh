#!/bin/bash -x

# Build libmobilecoin.a and *.h artifacts for mobilecoin-go's include subdir
#
# prerequesites:
# 1. run on MacOS
#    a. will cross compile for other flavor (x86/aarch) of MacOS and x86 Linux
#    b. can also run on Linux, but will only build for x86 Linux
# 2. libmobilecoin.git should be cloned and in the same parent directory as mobilecoin-go (../libmobilecoin)
#     cd ..; git clone https://github.com/mobilecoinofficial/libmobilecoin.git --recurse-submodules
# 3.  The protobuf compiler should already be installed

cd ../libmobilecoin/libmobilecoin

# build attestation code to expect enclave on true hardware
export SGX_MODE=HW
# IAS_MODE=PROD for dual compatibility with current mainnet and future mainnet
# (as well as current testnet, which is already upgraded to DCAP)
export IAS_MODE=PROD

OS=$(uname -s)

case ${OS} in
    Darwin)
        # MacOS
        # build for MacOS on x86 and aarch64; and, linux on x86
        declare -a TARGETS=(x86_64-apple-darwin aarch64-apple-darwin x86_64-unknown-linux-gnu)

        # rust current builds on MacOS targeting MacOS 11.0 and later.
        # force this build to be consistent to avoid ld warnings from go.
        export MACOSX_DEPLOYMENT_TARGET=11.0

        # make sure linux cross compiling tools are installed
        brew tap SergioBenitez/osxct
        brew install x86_64-unknown-linux-gnu
        export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-unknown-linux-gnu-gcc
        ;;
    Linux)
        # Linux
        declare -a TARGETS=(x86_64-unknown-linux-gnu)
        ;;
    *)
        echo "Unsupported OS"
        exit 1
        ;;
esac

# make sure rust support for all of our target platforms is installed
for t in ${TARGETS[@]}; do
    rustup target add $t
done

# build the libraries
for t in ${TARGETS[@]}; do
    cargo build --release --target $t
done

case ${OS} in
    Darwin)
    # combine to a universal MacOS library
    lipo -create target/aarch64-apple-darwin/release/libmobilecoin.a target/x86_64-apple-darwin/release/libmobilecoin.a -output target/release/libmobilecoin.a
    # copy the universal MacOS library into mobilecoin-go's include subdir
    cp target/release/libmobilecoin.a ../../mobilecoin-go/include
    ;;
esac

# copy and rename the linux library
cp target/x86_64-unknown-linux-gnu/release/libmobilecoin.a target/release/libmobilecoin_linux.a

# copy headers and linux library in into mobilecoin-go's include subdir
cp include/* ../../mobilecoin-go/include
cp target/release/libmobilecoin_linux.a ../../mobilecoin-go/include
