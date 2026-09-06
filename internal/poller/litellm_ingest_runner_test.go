package poller

import "testing"

func TestLiteLLMRunnerContract(t *testing.T) {
	// The concrete sync-cycle tests are added with the runner implementation;
	// this compilation contract prevents wiring an incompatible source runtime.
	var _ interface{ Status() Status } = (*LiteLLMIngestRunner)(nil)
}
