package controller

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"

	dnsapi "github.com/AS214933/derpers-contorller/internal/dns"
)

type reconciliationDNS struct {
	records    map[string]dnsapi.Record
	operations []string
	failDelete string
}

func newReconciliationDNS(records []dnsapi.Record) *reconciliationDNS {
	p := &reconciliationDNS{records: map[string]dnsapi.Record{}}
	for _, r := range records {
		p.records[r.ID] = r
	}
	return p
}
func (p *reconciliationDNS) List(context.Context, string) ([]dnsapi.Record, error) {
	ids := make([]string, 0, len(p.records))
	for id := range p.records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]dnsapi.Record, 0, len(ids))
	for _, id := range ids {
		out = append(out, p.records[id])
	}
	return out, nil
}
func (p *reconciliationDNS) Put(_ context.Context, r dnsapi.Record) (dnsapi.Record, error) {
	if r.ID == "" {
		r.ID = "created-" + r.Type
	}
	p.operations = append(p.operations, "put:"+r.ID)
	p.records[r.ID] = r
	return r, nil
}
func (p *reconciliationDNS) Delete(_ context.Context, r dnsapi.Record) error {
	p.operations = append(p.operations, "delete:"+r.ID)
	if p.failDelete == r.ID {
		return errors.New("simulated provider deletion failure")
	}
	delete(p.records, r.ID)
	return nil
}

const reconciliationHostname = "hk.derp.example.test"

func reconciliationRecord(id, kind, value string) dnsapi.Record {
	return dnsapi.Record{ID: id, Name: reconciliationHostname, Type: kind, Value: value}
}

func TestDNSReconcileImportedDuplicatesCannotRetainStaleAddresses(t *testing.T) {
	owned := []dnsapi.Record{
		reconciliationRecord("a-1", "A", "203.0.113.10"),
		reconciliationRecord("a-2", "A", "203.0.113.11"),
		reconciliationRecord("v6-1", "AAAA", "2001:db8::1"),
		reconciliationRecord("v6-2", "AAAA", "2001:db8::2"),
		reconciliationRecord("owned-txt", "TXT", "preserve owned non-address record"),
	}
	current := append(append([]dnsapi.Record{}, owned...), reconciliationRecord("external-txt", "TXT", "preserve external record"))
	p := newReconciliationDNS(current)
	desired := []dnsapi.Record{
		reconciliationRecord("", "A", "203.0.113.20"),
		reconciliationRecord("", "AAAA", "2001:db8::20"),
	}
	var checkpoint []dnsapi.Record
	checkpoints := 0
	err := reconcileDNSRecords(context.Background(), p, reconciliationHostname, desired, owned, current, func(records []dnsapi.Record) error {
		checkpoint = append([]dnsapi.Record{}, records...)
		checkpoints++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	wantOperations := []string{"put:a-1", "put:v6-1", "delete:v6-2", "delete:a-2"}
	if !reflect.DeepEqual(p.operations, wantOperations) {
		t.Fatalf("retained addresses must be updated before deleting owned extras: %v", p.operations)
	}
	if checkpoints != 4 || len(checkpoint) != 3 || len(p.records) != 4 {
		t.Fatalf("wrong persisted ownership/remote records: checkpoints=%d owned=%v remote=%v", checkpoints, checkpoint, p.records)
	}
	if p.records["a-1"].Value != desired[0].Value || p.records["v6-1"].Value != desired[1].Value {
		t.Fatalf("new addresses were not written: %v", p.records)
	}
	if _, exists := p.records["a-2"]; exists {
		t.Fatal("duplicate A record still routes to the old IPv4 address")
	}
	if _, exists := p.records["v6-2"]; exists {
		t.Fatal("duplicate AAAA record still routes to the old IPv6 address")
	}
	for _, id := range []string{"owned-txt", "external-txt"} {
		if p.records[id].Value == "" {
			t.Fatalf("unrelated record %s was deleted", id)
		}
	}
}

func TestDNSReconcileConflictsAreCheckedBeforeAnyMutation(t *testing.T) {
	owned := []dnsapi.Record{
		reconciliationRecord("a-1", "A", "203.0.113.10"),
		reconciliationRecord("a-2", "A", "203.0.113.11"),
		reconciliationRecord("v6-1", "AAAA", "2001:db8::1"),
	}
	for _, kind := range []string{"A", "AAAA", "CNAME", "changed-duplicate", "changed-removed-type"} {
		t.Run(kind, func(t *testing.T) {
			current := append([]dnsapi.Record{}, owned...)
			switch kind {
			case "changed-duplicate":
				current[1].Value = "203.0.113.99"
			case "changed-removed-type":
				current[2].Value = "2001:db8::99"
			default:
				current = append(current, reconciliationRecord("external-conflict", kind, "external.example.test"))
			}
			p := newReconciliationDNS(current)
			persisted := false
			err := reconcileDNSRecords(context.Background(), p, reconciliationHostname, []dnsapi.Record{reconciliationRecord("", "A", "203.0.113.20")}, owned, current, func([]dnsapi.Record) error {
				persisted = true
				return nil
			})
			if err == nil || len(p.operations) != 0 || persisted {
				t.Fatalf("conflict must fail before DNS writes or ownership updates: err=%v operations=%v persisted=%v", err, p.operations, persisted)
			}
		})
	}
}

func TestDNSReconcileUsesExistingDuplicateAndRemovesDisabledIPv6(t *testing.T) {
	owned := []dnsapi.Record{
		reconciliationRecord("missing-a", "A", "203.0.113.10"),
		reconciliationRecord("existing-a", "A", "203.0.113.11"),
		reconciliationRecord("existing-v6", "AAAA", "2001:db8::1"),
		reconciliationRecord("other-type", "TXT", "preserve"),
	}
	current := append([]dnsapi.Record{}, owned[1:]...)
	p := newReconciliationDNS(current)
	var checkpoint []dnsapi.Record
	err := reconcileDNSRecords(context.Background(), p, reconciliationHostname, []dnsapi.Record{reconciliationRecord("", "A", "203.0.113.20")}, owned, current, func(records []dnsapi.Record) error {
		checkpoint = append([]dnsapi.Record{}, records...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.operations, []string{"put:existing-a", "delete:existing-v6"}) {
		t.Fatalf("missing old ID should not force a duplicate creation: %v", p.operations)
	}
	if len(checkpoint) != 2 || len(p.records) != 2 || p.records["existing-a"].Value != "203.0.113.20" || p.records["other-type"].Value != "preserve" {
		t.Fatalf("wrong records after IPv6 removal: owned=%v remote=%v", checkpoint, p.records)
	}
}

func TestDNSReconcileFailedDuplicateDeletionCanResumeFromCheckpoint(t *testing.T) {
	owned := []dnsapi.Record{
		reconciliationRecord("a-1", "A", "203.0.113.10"),
		reconciliationRecord("a-2", "A", "203.0.113.11"),
	}
	p := newReconciliationDNS(owned)
	p.failDelete = "a-2"
	desired := []dnsapi.Record{reconciliationRecord("", "A", "203.0.113.20")}
	checkpoint := append([]dnsapi.Record{}, owned...)
	persist := func(records []dnsapi.Record) error {
		checkpoint = append([]dnsapi.Record{}, records...)
		return nil
	}
	if err := reconcileDNSRecords(context.Background(), p, reconciliationHostname, desired, checkpoint, owned, persist); err == nil {
		t.Fatal("failed duplicate deletion was reported as success")
	}
	if checkpoint[0].Value != "203.0.113.20" || len(checkpoint) != 2 || p.records["a-2"].Value != "203.0.113.11" {
		t.Fatalf("failure lost the checkpoint for the successfully updated record: %v", checkpoint)
	}
	p.failDelete = ""
	current, _ := p.List(context.Background(), reconciliationHostname)
	if err := reconcileDNSRecords(context.Background(), p, reconciliationHostname, desired, checkpoint, current, persist); err != nil {
		t.Fatal(err)
	}
	if len(checkpoint) != 1 || len(p.records) != 1 || p.records["a-1"].Value != "203.0.113.20" {
		t.Fatalf("retry left a stale address: owned=%v remote=%v", checkpoint, p.records)
	}
}

func TestDNSReconcileCheckpointFailureStopsBeforePruning(t *testing.T) {
	owned := []dnsapi.Record{
		reconciliationRecord("a-1", "A", "203.0.113.10"),
		reconciliationRecord("a-2", "A", "203.0.113.11"),
	}
	p := newReconciliationDNS(owned)
	want := errors.New("database unavailable")
	err := reconcileDNSRecords(context.Background(), p, reconciliationHostname, []dnsapi.Record{reconciliationRecord("", "A", "203.0.113.20")}, owned, owned, func([]dnsapi.Record) error { return want })
	if !errors.Is(err, want) || !reflect.DeepEqual(p.operations, []string{"put:a-1"}) || len(p.records) != 2 {
		t.Fatalf("DNS side effects continued after ownership persistence failed: err=%v operations=%v", err, p.operations)
	}
}
