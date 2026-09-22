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
	p := isolatedKoinosProfile()
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

var liveEVMAcceptance = flag.Bool("isolated-evm-acceptance", false, "read the explicitly configured Prompt 03 isolated EVM development container")

func TestIsolatedEVMAcceptance(t *testing.T) {
	if !*liveEVMAcceptance {
		t.Skip("actual isolated EVM service not requested")
	}
	p := isolatedEVMProfile()
	s, e := NewEVMSnapshot(operator.Binding{Profile: p, RPC: "http://127.0.0.1:18083"})
	if e != nil {
		t.Fatal(e)
	}
	state, e := s.Read(context.Background(), []string{"0x70997970C51812dc3A010C7d01b50e0d17dc79C8"})
	if e != nil {
		t.Fatal(e)
	}
	if state.Paused || len(state.Validators) != 3 || state.CodeHash != p.CodeHash {
		t.Fatalf("unexpected EVM snapshot: %+v", state)
	}
	t.Logf("actual finalized EVM snapshot height=%d members=%d nonce=%s paused=%t", state.Height, len(state.Validators), state.Nonce, state.Paused)
}

func isolatedKoinosProfile() operator.Profile {
	return operator.Profile{SchemaVersion: 1, ID: "prompt03-koinos", Name: "Isolated Prompt 03", Family: "koinos", Environment: "local", NetworkID: "EiDdmebKeAcWOVxSQFyWCB8vcgEaDGDz75mWO9EhW3FnFA==", BridgeChainID: 31337, Contract: "1GMqNyFKh19QjhjfUkWC8yvWQ38Nsib9iZ", Codec: operator.KoinosCodec, SourceCommit: operator.KoinosSource, CodeHash: "e2a172bd00c3093a8e76e94a4ac2a92b559c73c372dea8fe1b94a03e45a08449", Reviewed: true, ReviewEvidence: "isolated development artifact only; production approval excluded"}
}
func isolatedEVMProfile() operator.Profile {
	return operator.Profile{SchemaVersion: 1, ID: "prompt03-evm", Name: "Isolated Prompt 03 EVM", Family: "evm", Environment: "local", NetworkID: "31337", BridgeChainID: 1, Contract: "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512", Codec: operator.EVMCodec, SourceCommit: operator.EVMSource, CodeHash: "8888608cab3c9e9054a20924b931696992c89cdcb0b8bf2dba3e78602d743913", Reviewed: true, ReviewEvidence: "isolated oversized development artifact only"}
}

func TestIsolatedEVMTransferRead(t *testing.T) {
	if !*liveEVMAcceptance || !*liveKoinosAcceptance {
		t.Skip("both actual isolated chains must be explicitly requested")
	}
	source := operator.Binding{Profile: isolatedEVMProfile(), RPC: "http://127.0.0.1:18083"}
	destination := isolatedKoinosProfile()
	snapshot, e := NewKoinosSnapshot(operator.Binding{Profile: destination, RPC: "http://127.0.0.1:18081"}, "http://127.0.0.1:18082")
	if e != nil {
		t.Fatal(e)
	}
	// Destination token is a reserved synthetic address. Deployment/support and
	// destination execution are separate acceptance steps, not claimed here.
	reader, e := NewEVMKoinosReader(source, snapshot, "1CAtc7wPVn9JUAcbV8jo8UfyzMoAHRaTPC", map[string]string{"0x5FbDB2315678afecb367f032d93F642f64180aa3": "162pT1wYEiKS9cXBbCsz6JHPFeGchtBdND"}, 86400000)
	if e != nil {
		t.Fatal(e)
	}
	const id = "a69784eddaa3aceb5afac7d93e9d01454dd73e7ade5b11d59e41a96241823486:0"
	got, e := reader.ReadTransfer(context.Background(), id)
	if e != nil {
		t.Fatal(e)
	}
	if got.Completed || got.BridgeEventsInTransaction != 1 || got.Transfer.Amount != "100000000" || got.Transfer.Payment != "0" || got.Transfer.Metadata != "prompt03 isolated transfer" || got.Transfer.Recipient != "1CAtc7wPVn9JUAcbV8jo8UfyzMoAHRaTPC" {
		t.Fatalf("wrong actual transfer observation: %+v", got)
	}
	digest, e := TransferDigest(destination, got.Transfer)
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("actual transfer reconstructed amount=%s completed=%t digest=%s", got.Transfer.Amount, got.Completed, digest)
}
