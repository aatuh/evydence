package config

import (
	"errors"
	"reflect"
	"testing"
)

func TestWorkerPayloadBudgetLeavesRoomForBoundedReadSentinel(t *testing.T) {
	settings, err := Parse(roleEnvironment(t, Worker, false, "EVYDENCE_WORKER_MAX_PAYLOAD_BYTES=9223372036854775806"), Worker)
	if err != nil || settings.Worker().MaxPayloadBytes != 9223372036854775806 {
		t.Fatal("largest supported bounded-read budget rejected", err)
	}
	settings, err = Parse(roleEnvironment(t, Worker, false, "EVYDENCE_WORKER_MAX_PAYLOAD_BYTES=9223372036854775807"), Worker)
	if !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(settings, Configuration{}) {
		t.Fatal("unusable sentinel-overflow budget returned startup settings", err)
	}
}
