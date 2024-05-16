#See https://github.com/open-quantum-safe/liboqs/issues/1199
FROM emscripten/emsdk:latest

RUN apt -y update
RUN apt -y install astyle cmake gcc ninja-build \
    libssl-dev python3-pytest python3-pytest-xdist \
    unzip xsltproc doxygen graphviz python3-yaml

COPY oqs-build.sh /bin/oqs-build
CMD [ "/bin/oqs-build" ]