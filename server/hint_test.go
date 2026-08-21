package server

import (
	"strings"
	"testing"
)

// The connect hint is the first thing an agent learns about the PowerShell
// dialect, and agents obey it: a recorded 2026-08-05 incident session never
// attempted $_, calculated properties, or the JVM tools because the hint said
// "no $ or {} or ;" - a claim that stopped being true when the safe-expression
// grammar landed. The hint must advertise what the dialect supports.
func TestWinRMConnectHintAdvertisesSafeExpressions(t *testing.T) {
	for _, want := range []string{"$_", "[math]::", "jps", "jstack", "FilterHashtable", "Test-NetConnection", "curl", "DSCheckLS.exe", "not recognized"} {
		if !strings.Contains(winrmConnectHint, want) {
			t.Errorf("winrm connect hint should mention %q\nhint: %s", want, winrmConnectHint)
		}
	}
	if strings.Contains(winrmConnectHint, "no $ or {}") {
		t.Errorf("winrm connect hint still carries the stale no-$-or-{} claim\nhint: %s", winrmConnectHint)
	}
}
