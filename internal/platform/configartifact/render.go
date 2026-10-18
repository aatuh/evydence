// Package configartifact renders code-owned configuration metadata. It does not
// capture process input, resolve credentials, open files or start providers.
package configartifact

import (
	"errors"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/aatuh/evydence/internal/platform/config"
)

const (
	ProductionEnvironmentPath  = ".production.env.example"
	ConfigurationReferencePath = "docs/reference/configuration.md"
	HelmReferencePath          = "docs/kubernetes.md"
)

var errInvalidSchema = errors.New("invalid configuration artifact schema")

// Render returns owned generated sections for the three canonical artifacts.
// Callers merge these sections with operator explanations; no live configuration
// or filesystem input belongs in this boundary.
func Render(definitions []config.Definition, native []config.NativeDefinition) (map[string][]byte, error) {
	definitions = slices.Clone(definitions)
	native = slices.Clone(native)
	slices.SortFunc(definitions, func(a, b config.Definition) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(native, func(a, b config.NativeDefinition) int { return strings.Compare(a.Name, b.Name) })
	for _, group := range [][]config.Definition{definitions, nativeDefinitions(native)} {
		names := make(map[string]bool, len(group))
		for _, d := range group {
			if !validName(d.Name) || names[d.Name] || (d.FileOption != "" && !validName(d.FileOption)) {
				return nil, errInvalidSchema
			}
			names[d.Name] = true
			if d.Secret && (d.Default != "" || d.ProductionDefault != "" || d.NonProductionDefault != "" || d.ConditionalDefault != "" || d.ProductionExample != "") {
				return nil, errInvalidSchema
			}
		}
	}
	environment, err := renderEnvironment(definitions)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		ProductionEnvironmentPath:  environment,
		ConfigurationReferencePath: renderReference(definitions, native, false),
		HelmReferencePath:          renderReference(definitions, native, true),
	}, nil
}

func nativeDefinitions(native []config.NativeDefinition) []config.Definition {
	result := make([]config.Definition, len(native))
	for i, d := range native {
		result[i] = d.Definition
	}
	return result
}

func validName(name string) bool {
	if name == "" || len(name) > 256 {
		return false
	}
	for i, c := range name {
		allowed := c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (i > 0 && c >= '0' && c <= '9')
		if !allowed {
			return false
		}
	}
	return true
}

func renderEnvironment(definitions []config.Definition) ([]byte, error) {
	lines := []string{"# Generated from internal/platform/config schema metadata.", "# Production examples are selections, not changes to runtime defaults.", "# Required secrets are deliberately empty. Supply real values outside source control.", ""}
	for _, d := range definitions {
		if d.Roles&^config.CLI == 0 {
			continue
		}
		value := d.Default
		if d.ProductionDefault != "" {
			value = d.ProductionDefault
		}
		if d.ProductionExample != "" {
			value = d.ProductionExample
		}
		if d.Secret {
			value = ""
		}
		encoded, err := environmentValue(value)
		if err != nil {
			return nil, err
		}
		lines = append(lines, "# "+oneLine(d.Description), "# Type: "+string(d.Kind)+"; processes: "+roles(d.Roles)+"; "+constraints(d), d.Name+"="+encoded)
		if d.FileOption != "" {
			lines = append(lines, "# Unset "+d.Name+" to use its private-file alternative instead:", "# "+d.FileOption+"=")
		}
		lines = append(lines, "")
	}
	lines = append(lines, "# Native SDK/platform inputs keep their separate resolution owners; see the configuration reference.")
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

func environmentValue(value string) (string, error) {
	if strings.ContainsAny(value, "$`") || strings.ContainsFunc(value, unicode.IsControl) {
		return "", errInvalidSchema
	}
	if strings.ContainsAny(value, ` \"'#;|&<>()[]{}`) {
		return strconv.Quote(value), nil
	}
	return value, nil
}

func renderReference(definitions []config.Definition, native []config.NativeDefinition, helm bool) []byte {
	lines := []string{"| Variable | Processes | Type | Default | Constraints | Notes |", "| --- | --- | --- | --- | --- | --- |"}
	for _, d := range definitions {
		if helm && d.Roles&^config.CLI == 0 {
			continue
		}
		lines = append(lines, referenceRow(d, "", helm))
		if d.FileOption != "" {
			file := config.Definition{Name: d.FileOption, Kind: config.Path, Roles: d.Roles, CLICommands: d.CLICommands, Secret: true, Description: "Private-file alternative for `" + d.Name + "`; unset the inline value. Runtime resolution retains the documented file checks."}
			lines = append(lines, referenceRow(file, "", helm))
		}
	}
	lines = append(lines, "", "Native inputs retain SDK/platform default, file and credential ownership; declarations do not resolve them.", "", "| Variable | Processes | Type | Default | Constraints | Notes |", "| --- | --- | --- | --- | --- | --- |")
	for _, d := range native {
		if helm && d.Roles&^config.CLI == 0 {
			continue
		}
		notes := "Resolution owner: " + string(d.Boundary) + "; pinned source: " + code(d.Source) + "."
		if len(d.Fallbacks) != 0 {
			notes += " Fallbacks: " + strings.Join(d.Fallbacks, ", ") + "."
		}
		if d.CaseSensitive {
			notes += " Choices are case-sensitive."
		}
		if d.Parameter != "" {
			notes += " Native parameter: " + code(d.Parameter) + "."
		}
		if d.Syntax != "" {
			notes += " Syntax: " + code(string(d.Syntax)) + "."
		}
		if len(d.ExactChoices) != 0 {
			notes += " Exact-case choices: " + choices(d.ExactChoices) + "."
		}
		if d.RejectEmpty {
			notes += " Present empty input is rejected."
		}
		if d.RejectControl {
			notes += " Control characters are rejected."
		}
		if d.MaxItemBytes > 0 {
			notes += " Item bytes <= " + strconv.Itoa(d.MaxItemBytes) + "."
		}
		for _, prefix := range d.AllowedHTTPPrefixes {
			notes += " Allowed HTTP prefix: " + code(prefix.String()) + "."
		}
		lines = append(lines, referenceRow(d.Definition, notes, helm))
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func referenceRow(d config.Definition, extra string, helm bool) string {
	notes := oneLine(d.Description)
	if helm {
		notes = rebaseLinks(notes)
	}
	if d.Required != 0 {
		notes += " Required for: " + roles(d.Required) + "."
	}
	if d.ProductionRequired != 0 {
		notes += " Required in production: " + roles(d.ProductionRequired) + "."
	}
	if d.ProductionExample != "" {
		notes += " Production example: " + code(d.ProductionExample) + "."
	}
	if len(d.Aliases) != 0 {
		notes += " Aliases: " + strings.Join(d.Aliases, ", ") + "."
	}
	if d.CLIFlag != "" {
		notes += " CLI flag: " + code("--"+d.CLIFlag) + "."
	}
	if d.CLICommands != 0 {
		notes += " CLI commands: " + cliCommands(d.CLICommands) + "."
	}
	if extra != "" {
		notes += " " + extra
	}
	kind := string(d.Kind)
	if d.Secret {
		kind += " (secret)"
	}
	values := []string{code(d.Name), roles(d.Roles), kind, defaults(d), constraints(d), notes}
	for i := range values {
		values[i] = strings.ReplaceAll(values[i], "|", `\|`)
	}
	return "| " + strings.Join(values, " | ") + " |"
}

func defaults(d config.Definition) string {
	values := []string{code(d.Default)}
	if d.ProductionDefault != "" {
		values = append(values, "production: "+code(d.ProductionDefault))
	}
	if d.NonProductionDefault != "" {
		values = append(values, "non-production: "+code(d.NonProductionDefault))
	}
	if d.DefaultPolicy != "" {
		values = append(values, oneLine(d.DefaultPolicy))
	}
	if d.DefaultWhenSet != "" {
		values = append(values, "when "+code(d.DefaultWhenSet)+": "+code(d.ConditionalDefault))
	}
	return strings.Join(values, "; ")
}

func constraints(d config.Definition) string {
	var values []string
	switch d.Kind {
	case config.Integer, config.Seconds, config.Duration:
		unit := ""
		if d.Kind == config.Seconds {
			unit = " seconds"
		}
		if d.Kind == config.Duration {
			unit = " nanoseconds"
		}
		values = append(values, strconv.FormatInt(d.Min, 10)+".."+strconv.FormatInt(d.Max, 10)+unit)
	}
	if d.MaxBytes > 0 {
		label := "input bytes <= "
		if d.Kind == config.Base64 {
			label = "decoded bytes <= "
		}
		values = append(values, label+strconv.Itoa(d.MaxBytes))
	}
	if d.MaxItems > 0 {
		values = append(values, "items <= "+strconv.Itoa(d.MaxItems))
	}
	if len(d.Allowed) != 0 {
		values = append(values, "choices: "+choices(d.Allowed))
	}
	if len(d.ProductionAllowed) != 0 {
		values = append(values, "production choices: "+choices(d.ProductionAllowed))
	}
	if d.ForbiddenInProduction {
		values = append(values, "production-forbidden override")
	}
	if d.EndpointPolicy != "" {
		values = append(values, "endpoint policy: "+string(d.EndpointPolicy))
	}
	if len(values) == 0 {
		return "schema validation"
	}
	return strings.Join(values, "; ")
}

func choices(values []string) string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = code(value)
	}
	return strings.Join(result, ", ")
}

func code(value string) string {
	if value == "" {
		return "unset"
	}
	if strings.TrimSpace(value) != value || strings.ContainsFunc(value, unicode.IsControl) || strings.Contains(value, "`") {
		value = strconv.Quote(value)
	}
	delimiter := strings.Repeat("`", strings.Count(value, "`")+1)
	return delimiter + value + delimiter
}

func oneLine(value string) string { return strings.Join(strings.Fields(value), " ") }

func cliCommands(mask config.CLICommand) string {
	var result []string
	for _, command := range []struct {
		mask config.CLICommand
		name string
	}{
		{config.CLIUpload, "upload commands"},
		{config.CLIGitHubBuild, "github-actions upload-build"},
		{config.CLIPreflight, "ci preflight"},
	} {
		if mask&command.mask != 0 {
			result = append(result, code(command.name))
		}
	}
	return strings.Join(result, ", ")
}

func roles(mask config.Role) string {
	var result []string
	for _, role := range []struct {
		mask config.Role
		name string
	}{
		{config.API, "API"}, {config.Worker, "worker"}, {config.Migrate, "migration"}, {config.CLI, "online CLI"},
		{config.WorkerProbe, "worker probe"}, {config.WorkerReplay, "parser replay"}, {config.WorkerReconcile, "reconciliation"},
	} {
		if mask&role.mask != 0 {
			result = append(result, role.name)
		}
	}
	return strings.Join(result, ", ")
}

var markdownLink = regexp.MustCompile(`\[[^\]]+\]\(([^\s)]+)\)`)

func rebaseLinks(text string) string {
	return markdownLink.ReplaceAllStringFunc(text, func(link string) string {
		parts := markdownLink.FindStringSubmatch(link)
		target, err := url.Parse(parts[1])
		if err != nil || target.IsAbs() || target.Host != "" || strings.HasPrefix(target.Path, "/") {
			return link
		}
		if target.Path == "" {
			target.Path = "reference/configuration.md"
		} else {
			target.Path = path.Join("reference", target.Path)
		}
		return strings.Replace(link, "("+parts[1]+")", "("+target.String()+")", 1)
	})
}
