.PHONY: all lib build test vet clean download-kats

BIN_DIR      = bin
KAT_DIR      = KAT
KAT_BASE_URL = https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/
TESTS        = sha-3bytetestvectors shakebytetestvectors

all: build

# Compile (and type-check) the package
build:
	go build ./...

# Produce a Go package archive (.a)
lib:
	mkdir -p $(BIN_DIR)
	go build -buildmode=archive -o $(BIN_DIR)/sha3.a .

vet:
	go vet ./...

test:
	@if [ ! -d "$(KAT_DIR)" ]; then \
		echo "KAT directory not found. Downloading KATs..."; \
		$(MAKE) download-kats; \
	fi
	go test -v ./...

clean:
	rm -rf $(KAT_DIR) $(BIN_DIR)

download-kats:
	mkdir -p $(KAT_DIR)
	@for test in $(TESTS); do \
		echo "Downloading $$test..."; \
		curl -fLO $(KAT_BASE_URL)$$test.zip; \
		mkdir -p $(KAT_DIR)/$$test; \
		unzip -o $$test.zip -d $(KAT_DIR)/$$test; \
		rm -f $$test.zip; \
	done
