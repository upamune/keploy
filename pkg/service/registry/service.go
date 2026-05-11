// Package registry provides a local file-backed mock registry.
package registry

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go.keploy.io/server/v3/config"
)

// Service manages registry entries.
type Service interface {
	Push(ctx context.Context) error
	Pull(ctx context.Context) error
	List(ctx context.Context) ([]string, error)
}

// Registry is a local filesystem-backed registry service.
type Registry struct {
	cfg *config.Config
}

// New creates a Registry service.
func New(cfg *config.Config) *Registry {
	return &Registry{cfg: cfg}
}

// Push copies a test-set's mocks into the registry under registry.name.
func (r *Registry) Push(ctx context.Context) error {
	src, err := r.mockPath(r.cfg.Registry.TestSet)
	if err != nil {
		return err
	}
	name, err := cleanName(r.cfg.Registry.Name)
	if err != nil {
		return err
	}
	dst := filepath.Join(r.registryRoot(), name)
	if err := os.RemoveAll(dst); err != nil {
		return fmt.Errorf("clear registry entry: %w", err)
	}
	return copyPath(ctx, src, dst)
}

// Pull copies registry.name mocks into registry.testSet.
func (r *Registry) Pull(ctx context.Context) error {
	name, err := cleanName(r.cfg.Registry.Name)
	if err != nil {
		return err
	}
	if _, err := cleanName(r.cfg.Registry.TestSet); err != nil {
		return fmt.Errorf("invalid test-set: %w", err)
	}
	src := filepath.Join(r.registryRoot(), name)
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("registry entry %q not found: %w", name, err)
	}
	dst, err := r.mockPathForWrite(r.cfg.Registry.TestSet)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dst); err != nil {
		return fmt.Errorf("clear destination mocks: %w", err)
	}
	return copyPath(ctx, src, dst)
}

// List returns registry entry names sorted lexicographically.
func (r *Registry) List(context.Context) ([]string, error) {
	entries, err := os.ReadDir(r.registryRoot())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read registry: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

func (r *Registry) registryRoot() string {
	if r.cfg.Registry.Path != "" {
		return r.cfg.Registry.Path
	}
	return filepath.Join(r.cfg.Path, "registry")
}

func (r *Registry) mockPath(testSet string) (string, error) {
	if _, err := cleanName(testSet); err != nil {
		return "", fmt.Errorf("invalid test-set: %w", err)
	}
	base := filepath.Join(r.cfg.Path, testSet)
	for _, candidate := range []string{filepath.Join(base, "mocks.yaml"), filepath.Join(base, "mocks")} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no mocks found in %s", base)
}

func (r *Registry) mockPathForWrite(testSet string) (string, error) {
	if _, err := cleanName(testSet); err != nil {
		return "", err
	}
	return filepath.Join(r.cfg.Path, testSet, "mocks.yaml"), nil
}

func cleanName(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("name is required")
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") || name == "." {
		return "", fmt.Errorf("%q must not contain path separators or parent references", name)
	}
	return name, nil
}

func copyPath(ctx context.Context, src, dst string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("stat source: %w", err)
	}
	if info.IsDir() {
		return copyDir(ctx, src, dst)
	}
	return copyFile(src, dst, info.Mode())
}

func copyDir(ctx context.Context, src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return copyFile(path, target, info.Mode())
	})
}

func copyFile(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
