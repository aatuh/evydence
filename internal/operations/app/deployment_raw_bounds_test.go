package app

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDeploymentInputsRejectRawBudgetsBeforeTrimmingAndTransactions(t *testing.T) {
	for _, kind := range []string{"product", "name", "kind"} {
		t.Run("environment "+kind, func(t *testing.T) {
			c, f, a, in := environmentCommandFixture(t)
			switch kind {
			case "product":
				in.ProductID = strings.Repeat(" ", 1024) + "product"
			case "name":
				in.Name = strings.Repeat(" ", MaxEnvironmentTextBytes) + "Production"
			case "kind":
				in.Kind = strings.Repeat(" ", MaxEnvironmentTextBytes) + "production"
			}
			if _, err := c.CreateDeploymentEnvironment(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.transactions != 0 {
				t.Fatal("raw environment budget reached transaction", err, f.transactions)
			}
		})
	}
	for _, kind := range []string{"environment", "release", "rollback", "artifact", "status", "UTC timestamp"} {
		t.Run("event "+kind, func(t *testing.T) {
			c, f, a, in := deploymentFixture(t)
			switch kind {
			case "environment":
				in.EnvironmentID = strings.Repeat(" ", 1024) + "env"
			case "release":
				in.ReleaseID = strings.Repeat(" ", 1024) + "release"
			case "rollback":
				in.RollbackOf = strings.Repeat(" ", 1024) + "prior"
			case "artifact":
				in.ArtifactIDs = []string{strings.Repeat(" ", 1024) + "artifact"}
			case "status":
				in.Status = strings.Repeat(" ", 64) + "succeeded"
			case "UTC timestamp":
				in.StartedAt = time.Date(1, 1, 1, 0, 0, 0, 0, time.FixedZone("offset", 3600))
			}
			if _, err := c.RecordDeployment(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.transactions != 0 {
				t.Fatal("raw deployment input reached transaction", kind, err, f.transactions)
			}
		})
	}
}
