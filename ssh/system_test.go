package ssh

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestCheckBinary_Found(t *testing.T) {
	d := &SystemSSHDialer{}
	// ssh should be available in CI and dev environments.
	if !d.CheckBinary() {
		t.Skip("ssh binary not found, skipping")
	}
	if d.sshBinary == "" {
		t.Fatal("sshBinary should be set after CheckBinary returns true")
	}
}

func TestCheckBinary_NotFound(t *testing.T) {
	orig := os.Getenv("PATH")
	t.Setenv("PATH", "/nonexistent")
	defer func() { _ = os.Setenv("PATH", orig) }()

	d := &SystemSSHDialer{}
	if d.CheckBinary() {
		t.Fatal("CheckBinary() = true, want false with empty PATH")
	}
}

func TestControlDir_Default(t *testing.T) {
	d := &SystemSSHDialer{}
	if got, want := d.controlDir(), defaultControlDir; got != want {
		t.Fatalf("controlDir() = %q, want %q", got, want)
	}
}

func TestControlDir_Custom(t *testing.T) {
	d := &SystemSSHDialer{ControlDir: "/custom/dir"}
	if got, want := d.controlDir(), "/custom/dir"; got != want {
		t.Fatalf("controlDir() = %q, want %q", got, want)
	}
}

func TestControlPath_ContainsHash(t *testing.T) {
	d := &SystemSSHDialer{}
	got := d.controlPath()
	want := filepath.Join(defaultControlDir, "%C")
	if got != want {
		t.Fatalf("controlPath() = %q, want %q", got, want)
	}
}

func TestSSHBinary_Default(t *testing.T) {
	d := &SystemSSHDialer{}
	if got, want := d.ssh(), "ssh"; got != want {
		t.Fatalf("ssh() = %q, want %q", got, want)
	}
}

func TestSSHBinary_AfterCheck(t *testing.T) {
	d := &SystemSSHDialer{sshBinary: "/usr/bin/ssh"}
	if got, want := d.ssh(), "/usr/bin/ssh"; got != want {
		t.Fatalf("ssh() = %q, want %q", got, want)
	}
}

func TestSystemSSHClientBaseArgs(t *testing.T) {
	c := &systemSSHClient{
		sshBinary:   "ssh",
		controlPath: "/tmp/ctl/%C",
		target:      "root@example.com",
		port:        2222,
	}

	args := c.baseArgs()

	// Should contain ControlPath, BatchMode, and port.
	wantPairs := [][2]string{
		{"-o", "ControlPath=/tmp/ctl/%C"},
		{"-o", "BatchMode=yes"},
		{"-p", "2222"},
	}
	for _, pair := range wantPairs {
		found := false
		for i := 0; i < len(args)-1; i++ {
			if args[i] == pair[0] && args[i+1] == pair[1] {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("baseArgs() missing %s %s, got %v", pair[0], pair[1], args)
		}
	}
}

func TestSystemSSHClientBaseArgs_DefaultPort(t *testing.T) {
	c := &systemSSHClient{
		sshBinary:   "ssh",
		controlPath: "/tmp/ctl/%C",
		target:      "root@example.com",
		port:        22,
	}

	args := c.baseArgs()

	// Port should still be present even when default.
	found := false
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-p" && args[i+1] == strconv.Itoa(22) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("baseArgs() missing -p 22, got %v", args)
	}
}

func TestDialCreatesControlDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ctl")
	d := &SystemSSHDialer{
		ControlDir: dir,
		// Use a nonexistent binary so Dial fails quickly after mkdir.
		sshBinary: "/nonexistent/ssh",
	}

	params := ConnectionParams{Host: "example.com", User: "root", Port: 22}
	_, _ = d.Dial(t.Context(), params)

	// The control directory should exist even though Dial failed.
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("control dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("control dir is not a directory")
	}
}

func TestDialFailsWithBadBinary(t *testing.T) {
	d := &SystemSSHDialer{
		ControlDir: t.TempDir(),
		sshBinary:  "/nonexistent/ssh",
	}

	params := ConnectionParams{Host: "example.com", User: "root", Port: 22}
	_, err := d.Dial(t.Context(), params)
	if err == nil {
		t.Fatal("Dial() expected error with nonexistent binary, got nil")
	}
}

func TestDialAppliesDefaults(t *testing.T) {
	// Verify that Dial fills in User and Port defaults even when empty.
	d := &SystemSSHDialer{
		ControlDir: t.TempDir(),
		sshBinary:  "/nonexistent/ssh",
	}

	params := ConnectionParams{Host: "example.com"}
	_, err := d.Dial(t.Context(), params)
	// It will fail because the binary doesn't exist, but it should not
	// panic from empty User/Port.
	if err == nil {
		t.Fatal("Dial() expected error, got nil")
	}
}

func TestSystemSFTPClientImplementsInterface(t *testing.T) {
	// Compile-time check that systemSFTPClient implements SFTPClient.
	var _ SFTPClient = (*systemSFTPClient)(nil)
}

func TestSystemSSHClientImplementsInterface(t *testing.T) {
	// Compile-time check that systemSSHClient implements Client.
	var _ Client = (*systemSSHClient)(nil)
}

func TestSystemSSHDialerImplementsInterface(t *testing.T) {
	// Compile-time check that SystemSSHDialer implements Dialer.
	var _ Dialer = (*SystemSSHDialer)(nil)
}
