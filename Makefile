CAJUNOS_ROOT ?= /srv/cajunos
PYTHON ?= python3

.PHONY: fetch lock validate binutils-stage1 gcc-stage1 linux-headers \
	glibc-headers-startfiles libgcc-bootstrap glibc-complete gcc-complete \
	kernel-first-boot fetch-base-system validate-base-system base-system-image \
	fetch-native-developer-git validate-native-developer-git \
	fetch-native-developer-archives validate-native-developer-archives \
	fetch-native-developer validate-native-developer \
	native-developer-preflight native-developer-seed

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

fetch-native-developer-git:
	$(PYTHON) scripts/fetch.py sync --root "$(CAJUNOS_ROOT)" \
		--manifest manifests/native-developer-seed.json \
		--lock locks/native-developer-seed.lock.json

validate-native-developer-git:
	$(PYTHON) scripts/fetch.py validate --root "$(CAJUNOS_ROOT)" \
		--manifest manifests/native-developer-seed.json \
		--lock locks/native-developer-seed.lock.json

fetch-native-developer-archives:
	$(PYTHON) scripts/fetch-native-developer-archives.py sync \
		--root "$(CAJUNOS_ROOT)"

validate-native-developer-archives:
	@: "$${CAJUNOS_GPGV:?set CAJUNOS_GPGV to the sealed gpgv executable}"
	@: "$${CAJUNOS_GPGV_LIBRARY_ROOT:?set CAJUNOS_GPGV_LIBRARY_ROOT to its sealed library root}"
	$(PYTHON) scripts/fetch-native-developer-archives.py validate \
		--root "$(CAJUNOS_ROOT)" \
		--gpgv "$${CAJUNOS_GPGV}" \
		--gpgv-library-root "$${CAJUNOS_GPGV_LIBRARY_ROOT}" \
		--gcc-prerequisites "$(CAJUNOS_ROOT)/upstream/gcc/contrib/prerequisites.sha512"

fetch-native-developer: fetch-native-developer-git fetch-native-developer-archives

validate-native-developer: validate-native-developer-git validate-native-developer-archives

native-developer-preflight:
	CAJUNOS_ROOT="$(CAJUNOS_ROOT)" scripts/build-native-developer-seed.sh --preflight-only

native-developer-seed:
	CAJUNOS_ROOT="$(CAJUNOS_ROOT)" scripts/build-native-developer-seed.sh
