#!/bin/bash
#See https://github.com/open-quantum-safe/liboqs/issues/1199
set -exuo pipefail


if test -f "/bin/external-oqs-build" ; then
    if test "${EXTERNAL_OQS_BUILD:=0}" -eq 0 ; then
        export EXTERNAL_OQS_BUILD=1
        /bin/external-oqs-build
        exit 0
    fi
fi

#Git URL liboqs, for when we will download the source from git
OQS_URL="${OQS_GIT_URL:=https://github.com/open-quantum-safe/liboqs.git}"
#The tag to checkout
OQS_TAG="${OQS_GIT_TAG:=main}"
#Where to save the build
OUT_DIRECTORY="${OQS_OUT_DIR:=/out}"
#We give the user the ability to use theoir own OQS source without having to do git shenanigans
OQS_LOCATION="${OQS_SOURCE:=/DOES/NOT/EXIST}"
#We give the user the ability to choose where to include the JS addons from
JS_ADDONS_LOCATION="${ADDONS_SOURCE:=/addons}"

#Define the functions we want to export from the WASM module
#We only really care about the functions that use the heap
KEM_FUNCS="_OQS_KEM_new,_OQS_KEM_keypair,_OQS_KEM_encaps,_OQS_KEM_decaps,_OQS_KEM_free"
SIG_FUNCS="_OQS_SIG_new,_OQS_SIG_keypair,_OQS_SIG_sign,_OQS_SIG_verify,_OQS_SIG_free"
#We export the malloc and free functions so we can allocate and free memory in the WASM module from JS
MEM_FUNCS="_malloc,_free,_OQS_MEM_secure_free,_OQS_MEM_insecure_free"
#KEM struct accessors
KEM_STRUCT_FUNCS="_OQS_KEM_get_method_name,_OQS_KEM_get_alg_version,_OQS_KEM_get_ind_cca,_OQS_KEM_get_length_public_key,_OQS_KEM_get_length_secret_key,_OQS_KEM_get_length_ciphertext,_OQS_KEM_get_length_shared_secret"
#SIG struct accessors
SIG_STRUCT_FUNCS="_OQS_SIG_get_method_name,_OQS_SIG_get_alg_version,_OQS_SIG_get_euf_cma,_OQS_SIG_get_length_public_key,_OQS_SIG_get_length_secret_key,_OQS_SIG_get_length_signature"
#Other functions that we need to export
OTHER_EXPORTS="_main"

ALL_EXPORTS="$KEM_FUNCS,$SIG_FUNCS,$MEM_FUNCS,$KEM_STRUCT_FUNCS,$SIG_STRUCT_FUNCS,$OTHER_EXPORTS"

BUILD_TMP_SRC_DIR="/tmp/oqs-src"

if test -d "$OQS_LOCATION" ; then
    echo "Using user provided OQS source"
    mkdir -p "$BUILD_TMP_SRC_DIR"
    cp -rv "$OQS_LOCATION"/* $BUILD_TMP_SRC_DIR/
else
    echo "Using OQS source from git"
    git clone "$OQS_URL" "$BUILD_TMP_SRC_DIR"
    pushd "$BUILD_TMP_SRC_DIR"
    git checkout $OQS_TAG
    popd
fi

#Now we have the sources prepared for building
cd "$BUILD_TMP_SRC_DIR"
#Recreate build dir
rm -rf build
mkdir build

cd build


emcmake cmake -GNinja \
    -DOQS_USE_OPENSSL=OFF \
    -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON \
    -DOQS_ALGS_ENABLED=All ..
emmake ninja

mkdir addons
cd addons
emcc -c \
    -O3 \
    -I "$(pwd)/../include" \
    "$JS_ADDONS_LOCATION"/*.c
mv *.o ../lib/
cd ..

cd lib

#We need to set the stack size to 16mb, otherwise Classic McEliece will not work
#We also need to export cwrap and malloc to be able to use the library in JS
emcc -o liboqs.js \
    -s EXPORTED_FUNCTIONS=$ALL_EXPORTS \
    -sEXPORTED_RUNTIME_METHODS=ccall,cwrap \
    -sSTACK_SIZE=16mb \
    -sWASM=1 \
    -sMODULARIZE -s 'EXPORT_NAME="CreateLibOQS"' \
    liboqs.a *.o

cp *.js *.wasm "$OUT_DIRECTORY"/