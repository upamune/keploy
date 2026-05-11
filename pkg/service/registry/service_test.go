package registry

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"go.keploy.io/server/v3/config"
)

func TestRegistryPushPullList(t *testing.T) {
	dir := t.TempDir()
	mockPath := filepath.Join(dir, "test-set-0", "mocks.yaml")
	if err := os.MkdirAll(filepath.Dir(mockPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mockPath, []byte("mock: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Path: dir,
		Registry: config.Registry{
			Path:    filepath.Join(dir, "registry"),
			Name:    "redis-baseline",
			TestSet: "test-set-0",
		},
	}
	svc := New(cfg)
	if err := svc.Push(context.Background()); err != nil {
		t.Fatalf("push: %v", err)
	}
	names, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(names) != 1 || names[0] != "redis-baseline" {
		t.Fatalf("names = %#v", names)
	}

	cfg.Registry.TestSet = "test-set-1"
	if err := svc.Pull(context.Background()); err != nil {
		t.Fatalf("pull: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "test-set-1", "mocks.yaml"))
	if err != nil {
		t.Fatalf("read pulled mock: %v", err)
	}
	if string(got) != "mock: true\n" {
		t.Fatalf("pulled mock = %q", got)
	}
}
