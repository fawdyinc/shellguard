package winrm

import (
	"testing"

	"github.com/fawdyinc/shellguard/ssh"
)

func TestWithWinRMDefaults(t *testing.T) {
	tests := []struct {
		name     string
		params   ssh.ConnectionParams
		wantPort int
		wantUser string
	}{
		{
			name:     "default HTTP",
			params:   ssh.ConnectionParams{Host: "win-server"},
			wantPort: 5985,
			wantUser: "Administrator",
		},
		{
			name:     "TLS port",
			params:   ssh.ConnectionParams{Host: "win-server", UseTLS: true},
			wantPort: 5986,
			wantUser: "Administrator",
		},
		{
			name:     "explicit port",
			params:   ssh.ConnectionParams{Host: "win-server", Port: 9999},
			wantPort: 9999,
			wantUser: "Administrator",
		},
		{
			name:     "explicit user",
			params:   ssh.ConnectionParams{Host: "win-server", User: "admin"},
			wantPort: 5985,
			wantUser: "admin",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := withWinRMDefaults(tc.params)
			if got.Port != tc.wantPort {
				t.Errorf("port = %d, want %d", got.Port, tc.wantPort)
			}
			if got.User != tc.wantUser {
				t.Errorf("user = %q, want %q", got.User, tc.wantUser)
			}
		})
	}
}

func TestNewWinRMManager(t *testing.T) {
	m := NewWinRMManager(nil)
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
	if m.dialer == nil {
		t.Error("expected non-nil dialer")
	}
	if m.connections == nil {
		t.Error("expected non-nil connections map")
	}
}

func TestWinRMFileInfo(t *testing.T) {
	fi := &winrmFileInfo{name: "test.txt", size: 1024, isDir: false}
	if fi.Name() != "test.txt" {
		t.Errorf("name = %q, want 'test.txt'", fi.Name())
	}
	if fi.Size() != 1024 {
		t.Errorf("size = %d, want 1024", fi.Size())
	}
	if fi.IsDir() {
		t.Error("expected not a directory")
	}

	dir := &winrmFileInfo{name: "logs", isDir: true}
	if !dir.IsDir() {
		t.Error("expected directory")
	}
}

func TestPsEscapeSingleQuote(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"it's", "it''s"},
		{"a'b'c", "a''b''c"},
		{"no quotes", "no quotes"},
	}
	for _, tc := range tests {
		got := psEscapeSingleQuote(tc.input)
		if got != tc.want {
			t.Errorf("psEscapeSingleQuote(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
