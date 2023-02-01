all: map-populator da-example ebpf-network-emulation ebpf-delay experiment vxlan-example

da-example:
	go generate ./cmd/da-example
	go build -o bin/da-example ./cmd/da-example

map-populator:
	go build -o bin/map-populator ./cmd/map-populator

ebpf-network-emulation:
	go generate ./cmd/ebpf-network-emulation
	go build -o bin/ebpf-network-emulation ./cmd/ebpf-network-emulation

ebpf-delay:
	go generate ./cmd/ebpf-delay
	go build -o bin/ebpf-delay ./cmd/ebpf-delay

experiment:
	go build -o bin/experiment ./cmd/experiment

vxlan-example:
	go generate ./cmd/vxlan-example
	go build -o bin/vxlan-example ./cmd/vxlan-example
