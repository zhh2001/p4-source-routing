package main

import (
	"reflect"
	"strings"
	"testing"

	p4configv1 "github.com/p4lang/p4runtime/go/p4/config/v1"
	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/zhh2001/p4runtime-go-controller/codec"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
	"google.golang.org/protobuf/proto"
)

const (
	testPortTableID  = 0x02000001
	testPortActionID = 0x01000001
)

func TestDefaultSwitches(t *testing.T) {
	want := []switchConfig{
		{Name: "s1", Address: "127.0.0.1:50051", DeviceID: 1, Ports: []uint64{1, 2, 3}},
		{Name: "s2", Address: "127.0.0.1:50052", DeviceID: 2, Ports: []uint64{1, 2}},
		{Name: "s3", Address: "127.0.0.1:50053", DeviceID: 3, Ports: []uint64{1, 2}},
		{Name: "s4", Address: "127.0.0.1:50054", DeviceID: 4, Ports: []uint64{1, 2, 3}},
	}
	if got := defaultSwitches(); !reflect.DeepEqual(got, want) {
		t.Fatalf("defaultSwitches() = %#v, want %#v", got, want)
	}
}

func TestBuildPortEntry(t *testing.T) {
	pl := testPipeline(t, []byte("device-config"))
	entry, err := buildPortEntry(pl, 3)
	if err != nil {
		t.Fatal(err)
	}

	if entry.GetTableId() != testPortTableID {
		t.Errorf("table ID = %#x, want %#x", entry.GetTableId(), testPortTableID)
	}
	if len(entry.GetMatch()) != 1 {
		t.Fatalf("match count = %d, want 1", len(entry.GetMatch()))
	}
	match := entry.GetMatch()[0]
	if match.GetFieldId() != 1 || !reflect.DeepEqual(match.GetExact().GetValue(), []byte{3}) {
		t.Errorf("match = %v, want exact port 3", match)
	}
	action := entry.GetAction().GetAction()
	if action.GetActionId() != testPortActionID {
		t.Errorf("action ID = %#x, want %#x", action.GetActionId(), testPortActionID)
	}
	if len(action.GetParams()) != 1 {
		t.Fatalf("parameter count = %d, want 1", len(action.GetParams()))
	}
	parameter := action.GetParams()[0]
	if parameter.GetParamId() != 1 || !reflect.DeepEqual(parameter.GetValue(), []byte{3}) {
		t.Errorf("action parameter = %v, want port 3", parameter)
	}
}

func TestBuildPortEntryRejectsWidePort(t *testing.T) {
	if _, err := buildPortEntry(testPipeline(t, nil), 256); err == nil {
		t.Fatal("buildPortEntry accepted a port wider than the route-entry field")
	}
}

func TestBuildPortEntriesRejectsDuplicatePort(t *testing.T) {
	if _, err := buildPortEntries(testPipeline(t, nil), []uint64{1, 2, 1}); err == nil {
		t.Fatal("buildPortEntries accepted a duplicate port")
	}
}

func TestVerifyPipeline(t *testing.T) {
	expected := testPipeline(t, []byte("device-config"))
	actual := testPipeline(t, []byte("device-config"))
	if err := verifyPipeline(expected, actual); err != nil {
		t.Fatalf("verifyPipeline rejected equal pipelines: %v", err)
	}

	differentInfo := testPipeline(t, []byte("device-config"))
	differentInfo.Info().Tables[0].Size++
	if err := verifyPipeline(expected, differentInfo); err == nil {
		t.Fatal("verifyPipeline accepted different P4Info")
	}
	if err := verifyPipeline(expected, testPipeline(t, []byte("other-config"))); err == nil {
		t.Fatal("verifyPipeline accepted different device configuration")
	}
	if err := verifyPipeline(expected, nil); err == nil {
		t.Fatal("verifyPipeline accepted an empty readback")
	}
}

func TestVerifyPortEntries(t *testing.T) {
	pl := testPipeline(t, nil)
	entries := buildEntries(t, pl, 3, 1, 2)
	if err := verifyPortEntries(pl, []uint64{1, 2, 3}, entries); err != nil {
		t.Fatalf("verifyPortEntries rejected the exact port set: %v", err)
	}
}

func TestVerifyPortEntriesRejectsIncorrectReadback(t *testing.T) {
	pl := testPipeline(t, nil)
	base := buildEntries(t, pl, 1, 2, 3)

	tests := []struct {
		name    string
		entries func() []*p4v1.TableEntry
		want    string
	}{
		{name: "missing port", entries: func() []*p4v1.TableEntry { return cloneEntries(base[:2]) }, want: "missing port 3"},
		{name: "extra port", entries: func() []*p4v1.TableEntry { return buildEntries(t, pl, 1, 2, 3, 4) }, want: "unexpected port 4"},
		{name: "duplicate port", entries: func() []*p4v1.TableEntry {
			entries := cloneEntries(base)
			entries = append(entries, proto.Clone(base[0]).(*p4v1.TableEntry))
			return entries
		}, want: "port 1 appears more than once"},
		{name: "nil entry", entries: func() []*p4v1.TableEntry {
			entries := cloneEntries(base)
			entries[0] = nil
			return entries
		}, want: "entry 0 is nil"},
		{name: "wrong table", entries: mutateEntries(base, func(entry *p4v1.TableEntry) { entry.TableId++ }), want: "does not identify table"},
		{name: "default entry", entries: mutateEntries(base, func(entry *p4v1.TableEntry) { entry.IsDefaultAction = true }), want: "does not identify table"},
		{name: "missing match", entries: mutateEntries(base, func(entry *p4v1.TableEntry) { entry.Match = nil }), want: "has 0 match fields"},
		{name: "extra match", entries: mutateEntries(base, func(entry *p4v1.TableEntry) {
			entry.Match = append(entry.Match, proto.Clone(entry.Match[0]).(*p4v1.FieldMatch))
		}), want: "has 2 match fields"},
		{name: "wrong field", entries: mutateEntries(base, func(entry *p4v1.TableEntry) { entry.Match[0].FieldId++ }), want: "wrong match field"},
		{name: "wrong match kind", entries: mutateEntries(base, func(entry *p4v1.TableEntry) {
			entry.Match[0].FieldMatchType = &p4v1.FieldMatch_Lpm{Lpm: &p4v1.FieldMatch_LPM{Value: []byte{1}, PrefixLen: 8}}
		}), want: "wrong match field"},
		{name: "noncanonical match", entries: mutateEntries(base, func(entry *p4v1.TableEntry) { entry.Match[0].GetExact().Value = []byte{0, 1} }), want: "non-canonical"},
		{name: "out-of-range match", entries: mutateEntries(base, func(entry *p4v1.TableEntry) { entry.Match[0].GetExact().Value = []byte{1, 0} }), want: "exceeds 8-bit range"},
		{name: "missing action", entries: mutateEntries(base, func(entry *p4v1.TableEntry) { entry.Action = nil }), want: "no direct action"},
		{name: "wrong action", entries: mutateEntries(base, func(entry *p4v1.TableEntry) { entry.GetAction().GetAction().ActionId++ }), want: "wrong action"},
		{name: "missing parameter", entries: mutateEntries(base, func(entry *p4v1.TableEntry) { entry.GetAction().GetAction().Params = nil }), want: "has 0 action parameters"},
		{name: "extra parameter", entries: mutateEntries(base, func(entry *p4v1.TableEntry) {
			params := entry.GetAction().GetAction().Params
			entry.GetAction().GetAction().Params = append(params, proto.Clone(params[0]).(*p4v1.Action_Param))
		}), want: "has 2 action parameters"},
		{name: "wrong parameter", entries: mutateEntries(base, func(entry *p4v1.TableEntry) { entry.GetAction().GetAction().Params[0].ParamId++ }), want: "wrong action parameter"},
		{name: "noncanonical parameter", entries: mutateEntries(base, func(entry *p4v1.TableEntry) { entry.GetAction().GetAction().Params[0].Value = []byte{0, 1} }), want: "non-canonical"},
		{name: "different action port", entries: mutateEntries(base, func(entry *p4v1.TableEntry) {
			entry.GetAction().GetAction().Params[0].Value = codec.MustEncodeUint(2, 9)
		}), want: "maps port 1 to port 2"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := verifyPortEntries(pl, []uint64{1, 2, 3}, test.entries())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("verifyPortEntries() error = %v, want text %q", err, test.want)
			}
		})
	}
}

func TestVerifyPortEntriesRejectsDuplicateExpectedPort(t *testing.T) {
	pl := testPipeline(t, nil)
	if err := verifyPortEntries(pl, []uint64{1, 1}, buildEntries(t, pl, 1)); err == nil {
		t.Fatal("verifyPortEntries accepted a duplicate expected port")
	}
}

func testPipeline(t *testing.T, deviceConfig []byte) *pipeline.Pipeline {
	t.Helper()
	info := &p4configv1.P4Info{
		Tables: []*p4configv1.Table{{
			Preamble: &p4configv1.Preamble{Id: testPortTableID, Name: portTableName},
			Size:     256,
			MatchFields: []*p4configv1.MatchField{{
				Id:       1,
				Name:     portFieldName,
				Bitwidth: 8,
				Match: &p4configv1.MatchField_MatchType_{
					MatchType: p4configv1.MatchField_EXACT,
				},
			}},
			ActionRefs: []*p4configv1.ActionRef{{Id: testPortActionID}},
		}},
		Actions: []*p4configv1.Action{{
			Preamble: &p4configv1.Preamble{Id: testPortActionID, Name: portActionName},
			Params: []*p4configv1.Action_Param{{
				Id:       1,
				Name:     portParamName,
				Bitwidth: 9,
			}},
		}},
	}
	pl, err := pipeline.New(info, deviceConfig)
	if err != nil {
		t.Fatal(err)
	}
	return pl
}

func buildEntries(t *testing.T, pl *pipeline.Pipeline, ports ...uint64) []*p4v1.TableEntry {
	t.Helper()
	entries := make([]*p4v1.TableEntry, 0, len(ports))
	for _, port := range ports {
		entry, err := buildPortEntry(pl, port)
		if err != nil {
			t.Fatalf("buildPortEntry(%d): %v", port, err)
		}
		entries = append(entries, entry)
	}
	return entries
}

func cloneEntries(entries []*p4v1.TableEntry) []*p4v1.TableEntry {
	clones := make([]*p4v1.TableEntry, len(entries))
	for index, entry := range entries {
		clones[index] = proto.Clone(entry).(*p4v1.TableEntry)
	}
	return clones
}

func mutateEntries(base []*p4v1.TableEntry, mutate func(*p4v1.TableEntry)) func() []*p4v1.TableEntry {
	return func() []*p4v1.TableEntry {
		entries := cloneEntries(base)
		mutate(entries[0])
		return entries
	}
}
