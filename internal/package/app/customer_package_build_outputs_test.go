package app

import (
	"reflect"
	"testing"
)

func TestCustomerPackageBuildOutputSummariesPreserveOrderingAndOwnership(t *testing.T) {
	values := []CustomerPackageBuildOutput{{ArtifactID: "z", Digest: "sha256:b"}, {ArtifactID: "a", Digest: "sha256:z"}, {ArtifactID: "a", Digest: "sha256:a"}, {Digest: "sha256:unregistered"}, {ArtifactID: "a", Digest: "sha256:a"}}
	rows := CustomerPackageBuildOutputSummaries(values)
	want := []map[string]any{{"artifact_id": "", "digest": "sha256:unregistered"}, {"artifact_id": "a", "digest": "sha256:a"}, {"artifact_id": "a", "digest": "sha256:a"}, {"artifact_id": "a", "digest": "sha256:z"}, {"artifact_id": "z", "digest": "sha256:b"}}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("output summaries=%#v want=%#v", rows, want)
	}
	rows[0]["digest"] = "changed"
	if values[0].ArtifactID != "z" || values[3].Digest != "sha256:unregistered" {
		t.Fatal("summary sorting/output aliases source")
	}
	if empty := CustomerPackageBuildOutputSummaries(nil); empty == nil || len(empty) != 0 {
		t.Fatal("empty outputs must retain nonnil collection", empty)
	}
}
