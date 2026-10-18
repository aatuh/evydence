//go:build deployment

package deploymentcheck

import (
	"strings"
	"testing"
)

func TestDeploymentFixtureRejectsUnownedSelectors(t *testing.T) {
	for _, selection := range [][3]string{
		{"PRIVATE_PROGRAM", "api", "env"},
		{"helm", "--PRIVATE_FLAG", "env"},
		{"operator", "cli", "PRIVATE_MODE"},
		{"helm", "migrate", "files"},
	} {
		command, err := fixtureCommand(t.Context(), selection[0], selection[1], selection[2])
		if command != nil || err == nil || strings.Contains(err.Error(), "PRIVATE_") {
			t.Fatal("unsupported fixture selector reached process construction or diagnostics")
		}
	}
}
