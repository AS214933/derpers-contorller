package controller

import "testing"

func TestPublishedNodeExposesOnlyHealthMetrics(t *testing.T) {
	input := map[string]float64{"derper_up": 1, "derper_process_up": 1, "caddy_process_up": 1, "derper_metrics_up": 0, "derper_probe_timestamp_seconds": 1234, "derper_memory_usage_bytes": 1000, "derper_derp_bytes_sent": 2000, "untrusted_metric": 999}
	got := publicHealthMetrics(input)
	if len(got) != 5 {
		t.Fatalf("wrong public metrics: %+v", got)
	}
	for _, k := range []string{"derper_memory_usage_bytes", "derper_derp_bytes_sent", "untrusted_metric"} {
		if _, ok := got[k]; ok {
			t.Fatalf("private operational metric %q was exposed", k)
		}
	}
	got["derper_up"] = 0
	if input["derper_up"] != 1 {
		t.Fatal("redaction mutated the stored sample")
	}
}
