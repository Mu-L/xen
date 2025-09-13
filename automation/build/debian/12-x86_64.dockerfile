# syntax=docker/dockerfile:1
FROM --platform=linux/amd64 debian:bookworm
LABEL maintainer.name="The Xen Project"
LABEL maintainer.email="xen-devel@lists.xenproject.org"

ENV DEBIAN_FRONTEND=noninteractive

RUN <<EOF
#!/bin/bash
    set -eu

    useradd --create-home user

    apt-get update

    DEPS=(
        # Xen
        bison
        build-essential
        checkpolicy
        clang
        flex

        # Tools (general)
        ca-certificates
        cpio
        git-core
        pkg-config
        wget
        # libxenguest dombuilder
        libbz2-dev
        liblzma-dev
        liblzo2-dev
        libzstd-dev
        zlib1g-dev
        # libacpi
        acpica-tools
        # libxl
        uuid-dev
        libnl-3-dev
        libyajl-dev
        # RomBIOS
        bcc
        bin86
        # xentop
        libncurses5-dev
        # Python bindings
        python3-dev
        python3-setuptools
        # Golang bindings
        golang-go
        # Ocaml bindings/oxenstored
        ocaml-nox
        ocaml-findlib

        # for test phase, qemu-* jobs
        busybox-static
        expect
        ovmf
        qemu-system-x86

        # for build-each-commit-gcc
        ccache
    )

    apt-get -y --no-install-recommends install "${DEPS[@]}"

    rm -rf /var/lib/apt/lists*
EOF

USER user
WORKDIR /build
