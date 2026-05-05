package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	bb  "github.com/kosh/integration-test/bb_pb"
	pol "github.com/kosh/integration-test/policy_pb"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

func freePort() int {
	l, _ := net.Listen("tcp", ":0")
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitReady(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("service at %s not ready after %s", addr, timeout)
}

func buildAndStart(t *testing.T, dir, binary string, env []string) string {
	t.Helper()
	binPath := t.TempDir() + "/" + binary
	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/"+binary)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build %s: %v", binary, err)
	}
	proc := exec.Command(binPath)
	proc.Env = append(os.Environ(), env...)
	proc.Stdout = os.Stdout
	proc.Stderr = os.Stderr
	if err := proc.Start(); err != nil {
		t.Fatalf("start %s: %v", binary, err)
	}
	t.Cleanup(func() { proc.Process.Kill() })
	return binPath
}

func dial(t *testing.T, addr string) *grpc.ClientConn {
	t.Helper()
	// Use passthrough resolver so gRPC skips DNS lookup and connects directly.
	conn, err := grpc.NewClient(
		"passthrough:///"+addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient(%s): %v", addr, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// ─── kosh-coordinator gRPC tests ─────────────────────────────────────────────

func startCoordinator(t *testing.T) string {
	t.Helper()
	port := freePort()
	addr := fmt.Sprintf("localhost:%d", port)
	buildAndStart(t, "../kosh-coordinator", "coordinator",
		[]string{fmt.Sprintf("PORT=%d", port)})
	if err := waitReady(addr, 8*time.Second); err != nil {
		t.Fatalf("coordinator not ready: %v", err)
	}
	log.Printf("[coordinator] up on %s", addr)
	return addr
}

func TestCoordinator_PostAndRead(t *testing.T) {
	addr := startCoordinator(t)
	client := bb.NewBulletinBoardClient(dial(t, addr))
	ctx := context.Background()

	_, err := client.Post(ctx, &bb.PostRequest{Topic: "test-topic", Value: "hello-world"})
	if err != nil {
		t.Fatalf("Post failed: %v", err)
	}

	resp, err := client.Read(ctx, &bb.ReadRequest{Topic: "test-topic"})
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if !resp.Found {
		t.Fatal("Read: expected found=true")
	}
	if resp.Value != "hello-world" {
		t.Fatalf("Read: expected 'hello-world', got %q", resp.Value)
	}
	t.Logf("Post+Read OK: value=%q", resp.Value)
}

func TestCoordinator_ReadMissingTopic(t *testing.T) {
	addr := startCoordinator(t)
	client := bb.NewBulletinBoardClient(dial(t, addr))
	ctx := context.Background()

	resp, err := client.Read(ctx, &bb.ReadRequest{Topic: "does-not-exist"})
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if resp.Found {
		t.Fatal("expected found=false for missing topic")
	}
	t.Log("Read missing topic: correctly returned found=false")
}

func TestCoordinator_Watch_ReceivesImmediateValue(t *testing.T) {
	addr := startCoordinator(t)
	client := bb.NewBulletinBoardClient(dial(t, addr))
	bg := context.Background()

	// Post a value BEFORE opening the Watch stream (use background ctx, no deadline)
	_, err := client.Post(bg, &bb.PostRequest{Topic: "watch-topic", Value: "pre-posted"})
	if err != nil {
		t.Fatalf("Post: %v", err)
	}

	// Watch should immediately deliver the existing value
	watchCtx, cancel := context.WithTimeout(bg, 5*time.Second)
	defer cancel()
	stream, err := client.Watch(watchCtx, &bb.WatchRequest{Topic: "watch-topic"})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}

	event, err := stream.Recv()
	if err != nil {
		t.Fatalf("Watch Recv: %v", err)
	}
	if event.Value != "pre-posted" {
		t.Fatalf("Watch: expected 'pre-posted', got %q", event.Value)
	}
	t.Logf("Watch immediate delivery OK: value=%q", event.Value)
}

func TestCoordinator_Watch_ReceivesFutureValue(t *testing.T) {
	addr := startCoordinator(t)
	client := bb.NewBulletinBoardClient(dial(t, addr))
	bg := context.Background()

	// Open Watch BEFORE posting — use a separate context with enough timeout
	watchCtx, cancel := context.WithTimeout(bg, 5*time.Second)
	defer cancel()
	stream, err := client.Watch(watchCtx, &bb.WatchRequest{Topic: "future-topic"})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}

	// Post from a goroutine after short delay — background ctx (no deadline)
	go func() {
		time.Sleep(200 * time.Millisecond)
		client.Post(bg, &bb.PostRequest{
			Topic: "future-topic", Value: "arrived-later",
		})
	}()

	// Watch should receive it via streaming push (goroutine + channel broadcast)
	event, err := stream.Recv()
	if err != nil {
		t.Fatalf("Watch Recv future: %v", err)
	}
	if event.Value != "arrived-later" {
		t.Fatalf("Watch future: expected 'arrived-later', got %q", event.Value)
	}
	t.Logf("Watch streaming push OK: value=%q", event.Value)
}

func TestCoordinator_Clear(t *testing.T) {
	addr := startCoordinator(t)
	client := bb.NewBulletinBoardClient(dial(t, addr))
	ctx := context.Background()

	client.Post(ctx, &bb.PostRequest{Topic: "a", Value: "1"})
	client.Post(ctx, &bb.PostRequest{Topic: "b", Value: "2"})

	resp, err := client.Clear(ctx, &bb.ClearRequest{})
	if err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if resp.KeysCleared != 2 {
		t.Fatalf("Clear: expected 2 keys cleared, got %d", resp.KeysCleared)
	}

	// Verify gone
	r, _ := client.Read(ctx, &bb.ReadRequest{Topic: "a"})
	if r.Found {
		t.Fatal("expected topic 'a' to be gone after Clear")
	}
	t.Logf("Clear OK: removed %d keys", resp.KeysCleared)
}

func TestCoordinator_List(t *testing.T) {
	addr := startCoordinator(t)
	client := bb.NewBulletinBoardClient(dial(t, addr))
	ctx := context.Background()

	client.Post(ctx, &bb.PostRequest{Topic: "x", Value: "1"})
	client.Post(ctx, &bb.PostRequest{Topic: "y", Value: "2"})

	resp, err := client.List(ctx, &bb.ListRequest{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(resp.Topics) != 2 {
		t.Fatalf("List: expected 2 topics, got %d: %v", len(resp.Topics), resp.Topics)
	}
	t.Logf("List OK: topics=%v", resp.Topics)
}

// ─── kosh-policy gRPC tests ───────────────────────────────────────────────────

func startPolicy(t *testing.T) string {
	t.Helper()
	port := freePort()
	addr := fmt.Sprintf("localhost:%d", port)
	buildAndStart(t, "../kosh-policy", "policy",
		[]string{fmt.Sprintf("PORT=%d", port), "POLICY_FILE="})
	if err := waitReady(addr, 8*time.Second); err != nil {
		t.Fatalf("policy not ready: %v", err)
	}
	log.Printf("[policy] up on %s", addr)
	return addr
}

func TestPolicy_AddAndList(t *testing.T) {
	addr := startPolicy(t)
	client := pol.NewPolicyServiceClient(dial(t, addr))
	ctx := context.Background()

	addResp, err := client.AddPolicy(ctx, &pol.AddPolicyRequest{
		Policy: &pol.Policy{
			Name:             "cfo-approval",
			TxTag:            "treasury",
			MandatoryParties: []uint32{2},
			MinThreshold:     2,
		},
	})
	if err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if addResp.Id == 0 {
		t.Fatal("expected non-zero id from AddPolicy")
	}
	t.Logf("AddPolicy OK: id=%d", addResp.Id)

	listResp, err := client.ListPolicies(ctx, &pol.ListPoliciesRequest{})
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(listResp.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(listResp.Policies))
	}
	if listResp.Policies[0].Name != "cfo-approval" {
		t.Fatalf("unexpected policy name: %s", listResp.Policies[0].Name)
	}
	t.Logf("ListPolicies OK: %+v", listResp.Policies[0])
}

func TestPolicy_Validate_Pass(t *testing.T) {
	addr := startPolicy(t)
	client := pol.NewPolicyServiceClient(dial(t, addr))
	ctx := context.Background()

	client.AddPolicy(ctx, &pol.AddPolicyRequest{
		Policy: &pol.Policy{
			Name:             "cfo-required",
			TxTag:            "treasury",
			MandatoryParties: []uint32{2},
			MinThreshold:     2,
		},
	})

	resp, err := client.Validate(ctx, &pol.ValidateRequest{
		TxTag:          "treasury",
		SigningParties: []uint32{1, 2}, // party 2 present ✓
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !resp.Ok {
		t.Fatalf("expected validation to pass, got violation: %s", resp.ViolationMessage)
	}
	t.Log("Validate pass OK")
}

func TestPolicy_Validate_MissingMandatoryParty(t *testing.T) {
	addr := startPolicy(t)
	client := pol.NewPolicyServiceClient(dial(t, addr))
	ctx := context.Background()

	client.AddPolicy(ctx, &pol.AddPolicyRequest{
		Policy: &pol.Policy{
			Name:             "cfo-required",
			TxTag:            "treasury",
			MandatoryParties: []uint32{2},
			MinThreshold:     2,
		},
	})

	resp, err := client.Validate(ctx, &pol.ValidateRequest{
		TxTag:          "treasury",
		SigningParties: []uint32{1, 3}, // party 2 MISSING ✗
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if resp.Ok {
		t.Fatal("expected validation to fail (mandatory party 2 missing)")
	}
	if len(resp.MissingParties) == 0 {
		t.Fatal("expected MissingParties to be populated")
	}
	t.Logf("Validate correctly rejected: %s (missing=%v)", resp.ViolationMessage, resp.MissingParties)
}

func TestPolicy_Validate_BelowMinThreshold(t *testing.T) {
	addr := startPolicy(t)
	client := pol.NewPolicyServiceClient(dial(t, addr))
	ctx := context.Background()

	client.AddPolicy(ctx, &pol.AddPolicyRequest{
		Policy: &pol.Policy{Name: "need3", MinThreshold: 3},
	})

	resp, err := client.Validate(ctx, &pol.ValidateRequest{
		TxTag:          "any",
		SigningParties: []uint32{1, 2}, // only 2, need 3 ✗
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if resp.Ok {
		t.Fatal("expected min-threshold violation")
	}
	t.Logf("Validate min-threshold rejection OK: %s", resp.ViolationMessage)
}

func TestPolicy_RemovePolicy(t *testing.T) {
	addr := startPolicy(t)
	client := pol.NewPolicyServiceClient(dial(t, addr))
	ctx := context.Background()

	add, _ := client.AddPolicy(ctx, &pol.AddPolicyRequest{
		Policy: &pol.Policy{Name: "temp", TxTag: "x", MinThreshold: 1},
	})

	del, err := client.RemovePolicy(ctx, &pol.RemovePolicyRequest{Id: add.Id})
	if err != nil {
		t.Fatalf("RemovePolicy: %v", err)
	}
	if !del.Ok {
		t.Fatal("expected RemovePolicy to return ok=true")
	}

	list, _ := client.ListPolicies(ctx, &pol.ListPoliciesRequest{})
	if len(list.Policies) != 0 {
		t.Fatalf("expected 0 policies after remove, got %d", len(list.Policies))
	}
	t.Log("RemovePolicy OK")
}

// ─── Cross-service: coordinator + policy both running ─────────────────────────

func TestBothServicesRunAndRespondToRealCalls(t *testing.T) {
	coordAddr := startCoordinator(t)
	policyAddr := startPolicy(t)

	coordClient := bb.NewBulletinBoardClient(dial(t, coordAddr))
	polClient := pol.NewPolicyServiceClient(dial(t, policyAddr))
	ctx := context.Background()

	// Coordinator: post a sign request (as party daemon would)
	_, err := coordClient.Post(ctx, &bb.PostRequest{
		Topic: "sign_request_42_session_1",
		Value: `{"key_id":42,"subset":[1,2],"hash":"0xdeadbeef"}`,
	})
	if err != nil {
		t.Fatalf("coordinator Post: %v", err)
	}

	// Policy: add a policy and validate it
	polClient.AddPolicy(ctx, &pol.AddPolicyRequest{
		Policy: &pol.Policy{
			Name: "2-of-3", TxTag: "transfer",
			MinThreshold: 2,
		},
	})
	val, err := polClient.Validate(ctx, &pol.ValidateRequest{
		TxTag:          "transfer",
		SigningParties: []uint32{1, 2},
	})
	if err != nil {
		t.Fatalf("policy Validate: %v", err)
	}
	if !val.Ok {
		t.Fatalf("cross-service validation failed: %s", val.ViolationMessage)
	}

	// Coordinator: read the sign request back
	read, err := coordClient.Read(ctx, &bb.ReadRequest{Topic: "sign_request_42_session_1"})
	if err != nil {
		t.Fatalf("coordinator Read: %v", err)
	}
	if !read.Found {
		t.Fatal("coordinator: sign request not found after post")
	}

	t.Logf("Cross-service test OK — coordinator value=%q, policy validated OK", read.Value)
}
