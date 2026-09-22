package managed

import (
	"context"
	"flag"
	"testing"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
)

var liveKoinosAcceptance = flag.Bool("isolated-koinos-acceptance", false, "read the explicitly configured Prompt 03 isolated development containers")

// This opt-in check uses actual Koinos processes, not HTTP fixtures. The fixed
// development chain ID and reviewed artifact must match before state is read.
func TestIsolatedKoinosAcceptance(t *testing.T) {
	if !*liveKoinosAcceptance {
		t.Skip("actual isolated Koinos services not requested")
	}
	p := operator.Profile{SchemaVersion: 1, ID: "prompt03-koinos", Name: "Isolated Prompt 03", Family: "koinos", Environment: "local", NetworkID: "EiDdmebKeAcWOVxSQFyWCB8vcgEaDGDz75mWO9EhW3FnFA==", BridgeChainID: 31337, Contract: "1GMqNyFKh19QjhjfUkWC8yvWQ38Nsib9iZ", Codec: operator.KoinosCodec, SourceCommit: operator.KoinosSource, CodeHash: "e2a172bd00c3093a8e76e94a4ac2a92b559c73c372dea8fe1b94a03e45a08449", Reviewed: true, ReviewEvidence: "isolated development artifact only; production approval excluded"}
	s, e := NewKoinosSnapshot(operator.Binding{Profile: p, RPC: "http://127.0.0.1:18081"}, "http://127.0.0.1:18082")
	if e != nil {
		t.Fatal(e)
	}
	state, e := s.Read(context.Background(), "1CAtc7wPVn9JUAcbV8jo8UfyzMoAHRaTPC", nil)
	if e != nil {
		t.Fatal(e)
	}
	if state.Height != 68 || state.Nonce != 1 || state.Paused || len(state.Validators) != 3 || state.CodeHash != p.CodeHash {
		t.Fatalf("unexpected development snapshot: %+v", state)
	}
	t.Logf("actual irreversible bridge snapshot height=%d members=%d nonce=%d paused=%t", state.Height, len(state.Validators), state.Nonce, state.Paused)
}
