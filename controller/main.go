package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	p4infoPath := flag.String(
		"p4info",
		"build/source_routing.p4info.txtpb",
		"path to the P4Info text protobuf",
	)
	deviceConfigPath := flag.String(
		"device-config",
		"build/source_routing.json",
		"path to the BMv2 JSON device configuration",
	)
	verifyOnly := flag.Bool("verify-only", false, "verify current state without writing")
	timeout := flag.Duration("timeout", 30*time.Second, "overall configuration timeout")
	flag.Parse()

	if flag.NArg() != 0 {
		exitWithError(fmt.Errorf("unexpected positional arguments"))
	}
	if *timeout <= 0 {
		exitWithError(fmt.Errorf("timeout must be positive"))
	}

	expectedPipeline, err := loadPipeline(*p4infoPath, *deviceConfigPath)
	if err != nil {
		exitWithError(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	for _, spec := range defaultSwitches() {
		if err := configureSwitch(ctx, spec, expectedPipeline, *verifyOnly); err != nil {
			exitWithError(fmt.Errorf("%s: %w", spec.Name, err))
		}
		operation := "configured and verified"
		if *verifyOnly {
			operation = "verified"
		}
		fmt.Printf("%s: %s ports %v\n", spec.Name, operation, spec.Ports)
	}
}

func exitWithError(err error) {
	fmt.Fprintf(os.Stderr, "controller: %v\n", err)
	os.Exit(1)
}
