.ONESHELL:

SHA := $(shell git rev-parse --short=8 HEAD)
GITVERSION := $(shell git describe --long --all)
BUILDDATE := $(shell date -Iseconds)
VERSION := $(or ${GITHUB_TAG_NAME},$(shell git describe --tags --exact-match 2> /dev/null || git symbolic-ref -q --short HEAD || git rev-parse --short HEAD))

INSTALL = /usr/bin/install
INSTALL_PROGRAM = ${INSTALL} -m 755
INSTALL_DATA = ${INSTALL} -m 644

GO111MODULE := on

all: pam nss

.PHONY: pam
pam:
	CGO_CFLAGS='-g -O2'  \
	go build -ldflags "-w \
			-X 'github.com/metal-stack/v.Version=$(VERSION)' \
			-X 'github.com/metal-stack/v.Revision=$(GITVERSION)' \
			-X 'github.com/metal-stack/v.GitSHA1=$(SHA)' \
			-X 'github.com/metal-stacj/v.BuildDate=$(BUILDDATE)'" \
                 --buildmode=c-shared -o bin/pam_azuread.so ./cmd/pam-azuread
	strip bin/pam_azuread.so

.PHONY: nss
nss:
	CGO_CFLAGS='-g -O2 -D __LIB_NSS_NAME=azuread'  \
	go build -ldflags "-w \
			-X 'github.com/metal-stack/v.Version=$(VERSION)' \
			-X 'github.com/metal-stack/v.Revision=$(GITVERSION)' \
			-X 'github.com/metal-stack/v.GitSHA1=$(SHA)' \
			-X 'github.com/metal-stacj/v.BuildDate=$(BUILDDATE)'" \
	         --buildmode=c-shared -o bin/libnss_azuread.so.2 ./cmd/nss-azuread
	strip bin/libnss_azuread.so.2

.PHONY: clean
clean:
	rm -rf bin/*

install: all
	${INSTALL_DATA} bin/libnss_azuread.so.2 ${prefix}/lib/libnss_azuread.so.2
	${INSTALL_PROGRAM} bin/pam_azuread.so ${prefix}/usr/lib/x86_64-linux-gnu/security/pam_azuread.so
	${INSTALL_DATA} sample.yaml ${prefix}/etc/azuread.conf
