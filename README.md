# liboqs-wasm

A small demonstration of building [liboqs](https://github.com/open-quantum-safe/liboqs) for WebAssembly using Emscripten, and then using it in a browser.

**!!! THIS IS NOT MEANT FOR PRODUCTION USE !!!**

## Files

`./addons` - Contains 2 small C files that have a small `main()` function to appease Emscripten and also a bunch of accessor methods that allow JS code to access the fields of `OQS_KEM` and `OQS_SIG` structs.

`./docker-builder` - Contains the Dockerfile for the build container, and also a build script that builds the final JS/WASM files. It builds the static version of liboqs, and then adds the accessor methods from above. Please check the env vars there to see how it's behavior can be changed.

`./test-website` - Contains the test HTML page. Also contains a high-level wrapper script `liboqs_wrapper.mjs` that allows for conventient access and use of the relevant functions of liboqs. Also has a small script `server.py` that starts a webserver allowing to interact with the static website.

`./out` - Empty directory where the relevant JS and WASM files should be placed. `./test-website` contains symlinks to this directory.

## Building and running

1. Clone the repo
2. Build the docker image. From  the `./docker-builder` directory: `docker build -t oqs-wasm .`. This will create the `oqs-wasm` image with the toolchain.
3. From the same directory, run `docker run -it --rm -e OQS_GIT_TAG="0.10.0" -v "$(pwd)/../out:/out:rw" -v "$(pwd)/../addons:/addons:ro" oqs-wasm`. You can build from whatever tag is in the repo. If the var is not defined, the script will build from main.
4. Check that no errors are shown and that now, there are files `liboqs.js` and `liboqs.wasm` in the `./out` directory.
5. Go to the `./test-website` directory. From this directory, run `python server.py` to start the server.
6. In your browser (I tested on the last Chrome Beta) go to http://127.0.0.1:8000/ and play with the algorithms there.