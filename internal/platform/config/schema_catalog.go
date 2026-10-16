package config

import "slices"

// The code-owned catalogue is assembled once; callers receive owned copies.
// No process environment, files, network or provider startup is consulted.
var optionDefinitions = slices.Concat(
	runtimeDefinitions,
	apiDefinitions,
	workerDefinitions,
	storageDefinitions,
	providerDefinitions,
	cliDefinitions,
)
