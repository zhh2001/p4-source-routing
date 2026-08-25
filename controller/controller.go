package main

import (
	"bytes"
	"context"
	"fmt"
	"os"

	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/zhh2001/p4runtime-go-controller/client"
	"github.com/zhh2001/p4runtime-go-controller/codec"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
	"github.com/zhh2001/p4runtime-go-controller/tableentry"
	"google.golang.org/protobuf/proto"
)

const (
	portTableName  = "MyIngress.valid_egress_port"
	portFieldName  = "meta.requested_port"
	portActionName = "MyIngress.set_egress"
	portParamName  = "port"
)

type switchConfig struct {
	Name     string
	Address  string
	DeviceID uint64
	Ports    []uint64
}

func defaultSwitches() []switchConfig {
	return []switchConfig{
		{Name: "s1", Address: "127.0.0.1:50051", DeviceID: 1, Ports: []uint64{1, 2, 3}},
		{Name: "s2", Address: "127.0.0.1:50052", DeviceID: 2, Ports: []uint64{1, 2}},
		{Name: "s3", Address: "127.0.0.1:50053", DeviceID: 3, Ports: []uint64{1, 2}},
		{Name: "s4", Address: "127.0.0.1:50054", DeviceID: 4, Ports: []uint64{1, 2, 3}},
	}
}

func loadPipeline(p4infoPath, deviceConfigPath string) (*pipeline.Pipeline, error) {
	p4info, err := os.ReadFile(p4infoPath)
	if err != nil {
		return nil, fmt.Errorf("read P4Info: %w", err)
	}
	deviceConfig, err := os.ReadFile(deviceConfigPath)
	if err != nil {
		return nil, fmt.Errorf("read device config: %w", err)
	}
	loaded, err := pipeline.LoadText(p4info, deviceConfig)
	if err != nil {
		return nil, fmt.Errorf("load pipeline: %w", err)
	}
	return loaded, nil
}

func configureSwitch(
	ctx context.Context,
	spec switchConfig,
	expectedPipeline *pipeline.Pipeline,
	verifyOnly bool,
) error {
	var portEntries []*p4v1.TableEntry
	if !verifyOnly {
		var err error
		portEntries, err = buildPortEntries(expectedPipeline, spec.Ports)
		if err != nil {
			return fmt.Errorf("validate ports: %w", err)
		}
	}

	controller, err := client.Dial(
		ctx,
		spec.Address,
		client.WithDeviceID(spec.DeviceID),
		client.WithElectionID(client.ElectionID{Low: 1}),
		client.WithInsecure(),
	)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer controller.Close()

	if !verifyOnly {
		if err := controller.BecomePrimary(ctx); err != nil {
			return fmt.Errorf("arbitration: %w", err)
		}
		result, err := controller.SetPipeline(
			ctx,
			expectedPipeline,
			client.SetPipelineOptions{
				Action:     client.PipelineVerifyAndCommit,
				NoFallback: true,
			},
		)
		if err != nil {
			return fmt.Errorf("install pipeline: %w", err)
		}
		if result.Action != client.PipelineVerifyAndCommit {
			return fmt.Errorf("install pipeline: unexpected action %d", result.Action)
		}
		if err := programPorts(ctx, controller, spec.Ports, portEntries); err != nil {
			return err
		}
	}

	actualPipeline, err := controller.GetPipeline(ctx)
	if err != nil {
		return fmt.Errorf("read pipeline: %w", err)
	}
	if err := verifyPipeline(expectedPipeline, actualPipeline); err != nil {
		return err
	}

	table, ok := expectedPipeline.Table(portTableName)
	if !ok {
		return fmt.Errorf("pipeline has no table %q", portTableName)
	}
	entries, err := controller.ReadTableEntries(ctx, table.ID)
	if err != nil {
		return fmt.Errorf("read valid ports: %w", err)
	}
	if err := verifyPortEntries(expectedPipeline, spec.Ports, entries); err != nil {
		return fmt.Errorf("verify valid ports: %w", err)
	}
	return nil
}

func programPorts(
	ctx context.Context,
	controller *client.Client,
	ports []uint64,
	entries []*p4v1.TableEntry,
) error {
	if len(ports) != len(entries) {
		return fmt.Errorf("program ports: %d ports and %d entries", len(ports), len(entries))
	}
	for index, entry := range entries {
		port := ports[index]
		if err := controller.WriteTableEntry(ctx, client.UpdateInsert, entry); err != nil {
			return fmt.Errorf("write port %d entry: %w", port, err)
		}
	}
	return nil
}

func buildPortEntries(activePipeline *pipeline.Pipeline, ports []uint64) ([]*p4v1.TableEntry, error) {
	seen := make(map[uint64]struct{}, len(ports))
	entries := make([]*p4v1.TableEntry, 0, len(ports))
	for _, port := range ports {
		if _, duplicate := seen[port]; duplicate {
			return nil, fmt.Errorf("port %d appears more than once", port)
		}
		seen[port] = struct{}{}
		entry, err := buildPortEntry(activePipeline, port)
		if err != nil {
			return nil, fmt.Errorf("build port %d entry: %w", port, err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func buildPortEntry(activePipeline *pipeline.Pipeline, port uint64) (*p4v1.TableEntry, error) {
	matchValue, err := codec.EncodeUint(port, 8)
	if err != nil {
		return nil, fmt.Errorf("encode match: %w", err)
	}
	actionValue, err := codec.EncodeUint(port, 9)
	if err != nil {
		return nil, fmt.Errorf("encode action parameter: %w", err)
	}
	return tableentry.NewBuilder(activePipeline, portTableName).
		Match(portFieldName, tableentry.Exact(matchValue)).
		Action(portActionName, tableentry.Param(portParamName, actionValue)).
		Build()
}

func verifyPipeline(expected, actual *pipeline.Pipeline) error {
	if actual == nil {
		return fmt.Errorf("pipeline readback is empty")
	}
	if !proto.Equal(expected.Info(), actual.Info()) {
		return fmt.Errorf("P4Info readback differs from requested pipeline")
	}
	if !bytes.Equal(expected.DeviceConfig(), actual.DeviceConfig()) {
		return fmt.Errorf("device-config readback differs from requested pipeline")
	}
	return nil
}

func verifyPortEntries(
	activePipeline *pipeline.Pipeline,
	expectedPorts []uint64,
	entries []*p4v1.TableEntry,
) error {
	table, ok := activePipeline.Table(portTableName)
	if !ok {
		return fmt.Errorf("pipeline has no table %q", portTableName)
	}
	matchField, ok := table.MatchField(portFieldName)
	if !ok {
		return fmt.Errorf("table %q has no field %q", portTableName, portFieldName)
	}
	action, ok := activePipeline.Action(portActionName)
	if !ok {
		return fmt.Errorf("pipeline has no action %q", portActionName)
	}
	parameter, ok := action.Param(portParamName)
	if !ok {
		return fmt.Errorf("action %q has no parameter %q", portActionName, portParamName)
	}

	expected := make(map[uint64]struct{}, len(expectedPorts))
	for _, port := range expectedPorts {
		if _, exists := expected[port]; exists {
			return fmt.Errorf("expected port %d more than once", port)
		}
		expected[port] = struct{}{}
	}

	seen := make(map[uint64]struct{}, len(entries))
	for index, entry := range entries {
		if entry == nil {
			return fmt.Errorf("entry %d is nil", index)
		}
		if entry.GetTableId() != table.ID || entry.GetIsDefaultAction() {
			return fmt.Errorf("entry %d does not identify table %q", index, portTableName)
		}
		if len(entry.GetMatch()) != 1 {
			return fmt.Errorf("entry %d has %d match fields", index, len(entry.GetMatch()))
		}
		match := entry.GetMatch()[0]
		if match.GetFieldId() != matchField.ID || match.GetExact() == nil {
			return fmt.Errorf("entry %d has the wrong match field", index)
		}
		port, err := decodePort(match.GetExact().GetValue(), 8)
		if err != nil {
			return fmt.Errorf("entry %d has an invalid port match: %w", index, err)
		}

		tableAction := entry.GetAction()
		if tableAction == nil || tableAction.GetAction() == nil {
			return fmt.Errorf("entry %d has no direct action", index)
		}
		directAction := tableAction.GetAction()
		if directAction.GetActionId() != action.ID {
			return fmt.Errorf("entry %d has the wrong action", index)
		}
		if len(directAction.GetParams()) != 1 {
			return fmt.Errorf("entry %d has %d action parameters", index, len(directAction.GetParams()))
		}
		actionParameter := directAction.GetParams()[0]
		if actionParameter.GetParamId() != parameter.ID {
			return fmt.Errorf("entry %d has the wrong action parameter", index)
		}
		actionPort, err := decodePort(actionParameter.GetValue(), 9)
		if err != nil {
			return fmt.Errorf("entry %d has an invalid action port: %w", index, err)
		}
		if actionPort != port {
			return fmt.Errorf("entry %d maps port %d to port %d", index, port, actionPort)
		}
		if _, ok := expected[port]; !ok {
			return fmt.Errorf("unexpected port %d", port)
		}
		if _, duplicate := seen[port]; duplicate {
			return fmt.Errorf("port %d appears more than once", port)
		}
		seen[port] = struct{}{}
	}

	for _, port := range expectedPorts {
		if _, ok := seen[port]; !ok {
			return fmt.Errorf("missing port %d", port)
		}
	}
	return nil
}

func decodePort(value []byte, bitwidth int) (uint64, error) {
	port, err := codec.DecodeUint(value)
	if err != nil {
		return 0, err
	}
	canonical, err := codec.EncodeUint(port, bitwidth)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(value, canonical) {
		return 0, fmt.Errorf("non-canonical %d-bit encoding", bitwidth)
	}
	return port, nil
}
