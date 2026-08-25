P4C ?= p4c-bm2-ss
GO ?= go
PYTHON ?= python3

BUILD_DIR := build
P4_SOURCE := p4/source_routing.p4
P4_JSON := $(BUILD_DIR)/source_routing.json
P4INFO := $(BUILD_DIR)/source_routing.p4info.txtpb
CONTROLLER := $(BUILD_DIR)/controller

.PHONY: build test clean

build:
	mkdir -p $(BUILD_DIR)
	$(P4C) --std p4-16 --Werror --p4runtime-files $(P4INFO) \
		-o $(P4_JSON) $(P4_SOURCE)
	$(GO) build -trimpath -o $(CONTROLLER) ./controller

test: build
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v
	$(GO) test ./...
	$(GO) vet ./...

clean:
	rm -rf -- ./build
