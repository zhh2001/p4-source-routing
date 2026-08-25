P4C ?= p4c-bm2-ss
GO ?= go
PYTHON ?= python3
SUDO ?= sudo

BUILD_DIR := build
P4_SOURCE := p4/source_routing.p4
P4_JSON := $(BUILD_DIR)/source_routing.json
P4INFO := $(BUILD_DIR)/source_routing.p4info.txtpb
CONTROLLER := $(BUILD_DIR)/controller

.PHONY: build run test test-unit test-integration clean

build:
	mkdir -p $(BUILD_DIR)
	$(P4C) --std p4-16 --Werror --p4runtime-files $(P4INFO) \
		-o $(P4_JSON) $(P4_SOURCE)
	$(GO) build -trimpath -o $(CONTROLLER) ./controller

run: build
	$(SUDO) env PYTHONDONTWRITEBYTECODE=1 $(PYTHON) mininet/topology.py

test: test-unit test-integration

test-unit: build
	PYTHONPYCACHEPREFIX=$(BUILD_DIR)/pycache $(PYTHON) -m py_compile \
		mininet/topology.py tests/test_p4_structure.py tests/test_topology.py \
		tests/test_mininet_runtime.py tools/source_route.py \
		tests/test_source_route_packets.py tests/test_packet_paths.py
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s tests \
		-p 'test_p4_structure.py' -v
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s tests \
		-p 'test_topology.py' -v
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s tests \
		-p 'test_source_route_packets.py' -v
	$(GO) test ./...
	$(GO) vet ./...

test-integration: build
	$(SUDO) env PYTHONDONTWRITEBYTECODE=1 $(PYTHON) tests/test_mininet_runtime.py
	$(SUDO) env PYTHONDONTWRITEBYTECODE=1 $(PYTHON) tests/test_packet_paths.py

clean:
	rm -rf -- ./build
