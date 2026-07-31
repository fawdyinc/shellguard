package control

import (
	"context"
	"encoding/json"
	"testing"
)

// stubHandler accepts every connect so dispatch's response shape can be tested
// without a real transport.
type stubHandler struct{}

func (stubHandler) Connect(context.Context, ConnectParams) error       { return nil }
func (stubHandler) Disconnect(context.Context, DisconnectParams) error { return nil }
func (stubHandler) ConnectedHosts() []string                           { return nil }

// TestConnectResponseReportsTransportAndShell pins the on-the-wire connect
// response. fawdy-legacy asserts on the "transport" and "shell" keys, so this
// is a cross-repo interface: renaming or dropping either key breaks the caller.
func TestConnectResponseReportsTransportAndShell(t *testing.T) {
	cases := []struct {
		requested     string
		wantTransport string
		wantShell     string
	}{
		{"", "ssh", "bash"},
		{"ssh", "ssh", "bash"},
		{"winrm", "winrm", "powershell"},
		{"local", "local", "bash"},
	}

	s := &Server{handler: stubHandler{}}
	for _, tc := range cases {
		params, err := json.Marshal(ConnectParams{Host: "h1", Transport: tc.requested})
		if err != nil {
			t.Fatalf("marshal params: %v", err)
		}

		resp := s.dispatch(context.Background(), Request{Command: "connect", Params: params})
		if !resp.OK {
			t.Fatalf("transport %q: connect failed: %s", tc.requested, resp.Error)
		}

		var got map[string]string
		if err := json.Unmarshal(resp.Data, &got); err != nil {
			t.Fatalf("transport %q: unmarshal data: %v", tc.requested, err)
		}
		if got["transport"] != tc.wantTransport {
			t.Errorf("transport %q: data[transport] = %q, want %q", tc.requested, got["transport"], tc.wantTransport)
		}
		if got["shell"] != tc.wantShell {
			t.Errorf("transport %q: data[shell] = %q, want %q", tc.requested, got["shell"], tc.wantShell)
		}
		// The pre-existing keys must survive: callers still read them.
		if got["host"] != "h1" || got["key"] != "h1" {
			t.Errorf("transport %q: host/key changed: %v", tc.requested, got)
		}
	}
}

func TestNormalizeTransport(t *testing.T) {
	cases := map[string]string{"": "ssh", "ssh": "ssh", "winrm": "winrm", "local": "local"}
	for in, want := range cases {
		if got := normalizeTransport(in); got != want {
			t.Errorf("normalizeTransport(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShellForTransport(t *testing.T) {
	cases := map[string]string{"ssh": "bash", "winrm": "powershell", "local": "bash"}
	for in, want := range cases {
		if got := shellForTransport(in); got != want {
			t.Errorf("shellForTransport(%q) = %q, want %q", in, got, want)
		}
	}
}
