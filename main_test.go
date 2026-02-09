package main

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConformance(t *testing.T) {
	sdk.RunConformance(t, buildServer())
}

func TestTrackConformance(t *testing.T) {
	sdk.RunForTrack(t, buildServer(), registry.TrackIncidentReadiness)
}

func TestScanFindsAllMissingDetectionComponents(t *testing.T) {
	client := testClient(t)
	// Scan an empty workspace -- all four rules should fire.
	resp := invokeScan(t, client, t.TempDir())

	for _, ruleID := range []string{"DETECT-001", "DETECT-002", "DETECT-003", "DETECT-004"} {
		found := findByRule(resp.GetFindings(), ruleID)
		if len(found) == 0 {
			t.Errorf("expected at least one %s finding for empty workspace", ruleID)
		}
	}
}

func TestScanDetectsStructuredLogging(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	// testdata contains structured logging usage, so DETECT-001 should NOT fire.
	found := findByRule(resp.GetFindings(), "DETECT-001")
	if len(found) != 0 {
		t.Error("DETECT-001 should not fire when structured logging is present")
	}
}

func TestScanDetectsSecurityEventLogging(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	// testdata contains security event logging, so DETECT-002 should NOT fire.
	found := findByRule(resp.GetFindings(), "DETECT-002")
	if len(found) != 0 {
		t.Error("DETECT-002 should not fire when security event logging is present")
	}
}

func TestScanDetectsMonitoring(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	// testdata contains monitoring library references, so DETECT-003 should NOT fire.
	found := findByRule(resp.GetFindings(), "DETECT-003")
	if len(found) != 0 {
		t.Error("DETECT-003 should not fire when monitoring library is present")
	}
}

func TestScanDetectsErrorTracking(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	// testdata contains error tracking service references, so DETECT-004 should NOT fire.
	found := findByRule(resp.GetFindings(), "DETECT-004")
	if len(found) != 0 {
		t.Error("DETECT-004 should not fire when error tracking is present")
	}
}

func TestScanNoWorkspace(t *testing.T) {
	client := testClient(t)
	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}
	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings when no workspace provided, got %d", len(resp.GetFindings()))
	}
}

// --- helpers ---

func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file path")
	}
	return filepath.Join(filepath.Dir(filename), "testdata")
}

func testClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}

func invokeScan(t *testing.T, client pluginv1.PluginServiceClient, workspaceRoot string) *pluginv1.InvokeToolResponse {
	t.Helper()
	input, _ := structpb.NewStruct(map[string]any{"workspace_root": workspaceRoot})
	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool(scan): %v", err)
	}
	return resp
}

func findByRule(findings []*pluginv1.Finding, ruleID string) []*pluginv1.Finding {
	var result []*pluginv1.Finding
	for _, f := range findings {
		if f.GetRuleId() == ruleID {
			result = append(result, f)
		}
	}
	return result
}
