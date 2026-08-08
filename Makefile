CAJUNOS_ROOT ?= /srv/cajunos
PYTHON ?= python3

.PHONY: fetch lock validate binutils-stage1 gcc-stage1 linux-headers \
	glibc-headers-startfiles libgcc-bootstrap glibc-complete gcc-complete \
	kernel-first-boot fetch-base-system validate-base-system base-system-image

fetch:
	$(PYTHON) scripts/fetch.py sync --root "$(CAJUNOS_ROOT)"

lock:
	$(PYTHON) scripts/fetch.py update-lock --root "$(CAJUNOS_ROOT)"

validate:
	$(PYTHON) scripts/fetch.py validate --root "$(CAJUNOS_ROOT)"

binutils-stage1:
	CAJUNOS_ROOT="$(CAJUNOS_ROOT)" scripts/build-binutils-stage1.sh

gcc-stage1:
	CAJUNOS_ROOT="$(CAJUNOS_ROOT)" scripts/build-gcc-stage1.sh

linux-headers:
	CAJUNOS_ROOT="$(CAJUNOS_ROOT)" scripts/install-linux-headers.sh

glibc-headers-startfiles:
	CAJUNOS_ROOT="$(CAJUNOS_ROOT)" scripts/install-glibc-headers-startfiles.sh

libgcc-bootstrap:
	CAJUNOS_ROOT="$(CAJUNOS_ROOT)" scripts/build-libgcc-bootstrap.sh

glibc-complete:
	CAJUNOS_ROOT="$(CAJUNOS_ROOT)" scripts/build-glibc-complete.sh

gcc-complete:
	CAJUNOS_ROOT="$(CAJUNOS_ROOT)" scripts/build-gcc-complete.sh

kernel-first-boot:
	CAJUNOS_ROOT="$(CAJUNOS_ROOT)" scripts/build-kernel-first-boot.sh

fetch-base-system:
	$(PYTHON) scripts/fetch.py sync --root "$(CAJUNOS_ROOT)" \
		--manifest manifests/base-system.json --lock locks/base-system.lock.json

validate-base-system:
	$(PYTHON) scripts/fetch.py validate --root "$(CAJUNOS_ROOT)" \
		--manifest manifests/base-system.json --lock locks/base-system.lock.json

base-system-image:
	CAJUNOS_ROOT="$(CAJUNOS_ROOT)" scripts/build-base-system-image.sh
