.PHONY: all build test clean download-kats

all: build

KAT_DIR = KAT
KAT_BASE_URL = https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/
TESTS = sha-3bytetestvectors shakebytetestvectors

test:
	@if [ ! -d "$(KAT_DIR)" ]; then \
		echo "KAT directory not found. Downloading KATs..."; \
		$(MAKE) download-kats; \
	fi
	go test -v

build:
	go build

clean:
	rm -r $(KAT_DIR)

download-kats:
	mkdir -p $(KAT_DIR)
	@for test in $(TESTS); do \
		echo "Downloading $$test..."; \
		curl -O $(KAT_BASE_URL)$$test.zip; \
		mkdir -p $(KAT_DIR)/$$test; \
		unzip -o $$test.zip -d $(KAT_DIR)/$$test; \
		rm -f $$test.zip; \
	done
