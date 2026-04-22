package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// renderPipelineForTest emulates winrm.ReconstructPowerShellCommand for the
// round-trip property test. Keeping it here (rather than importing winrm)
// avoids an import cycle; the quoting rules mirror winrm/reconstruct.go.
func renderPipelineForTest(p *Pipeline) string {
	if p == nil {
		return ""
	}
	parts := make([]string, 0, len(p.Segments)*2)
	for _, seg := range p.Segments {
		if seg.Operator != "" {
			parts = append(parts, seg.Operator)
		}
		tokens := make([]string, 0, len(seg.Args)+1)
		tokens = append(tokens, seg.Command)
		for _, arg := range seg.Args {
			tokens = append(tokens, quoteForTest(arg))
		}
		parts = append(parts, strings.Join(tokens, " "))
	}
	return strings.Join(parts, " ")
}

func quoteForTest(s string) string {
	if s == "" {
		return "''"
	}
	if strings.HasPrefix(s, "-") || strings.HasPrefix(s, "@{") || strings.HasPrefix(s, "{") {
		return s
	}
	// Composite array/hashtable form like `Name,@{...}` — pass through so the
	// hashtable's internal quoting isn't wrapped in an outer pair.
	if strings.Contains(s, ",@{") {
		return s
	}
	if looksLikeEnvRef(s, 0) && len(s) >= 6 {
		return s
	}
	if isQuoteFreeToken(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func isQuoteFreeToken(s string) bool {
	// Leading `/` is a forward-slash path-like token (e.g. XPath `/Directory`,
	// `//Connector`) that the Ident lexer won't accept as a bare argument — it
	// must be reconstructed wrapped in quotes so it re-parses as a String.
	if strings.HasPrefix(s, "/") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.' || r == ':' || r == '*' || r == '\\' || r == '/':
		default:
			return false
		}
	}
	return true
}

// corpusEntry is one row in a corpus YAML file. See parser/testdata/corpus/
// for examples. As grammar workstreams land, flip `expect` on affected
// entries from "rejects" to "parses".
type corpusEntry struct {
	Command string `yaml:"command"`
	Source  string `yaml:"source"`
	Expect  string `yaml:"expect"`
	Reason  string `yaml:"reason"`
}

type corpusFile struct {
	Entries []corpusEntry `yaml:"entries"`
}

// TestCorpus drives data-driven parser validation off YAML fixtures in
// parser/testdata/corpus/. The harness exists to give an empirical view of
// what the parser accepts across real recorded sessions and known-dangerous
// patterns. Run with -v to see a reason-tag summary.
func TestCorpus(t *testing.T) {
	files, err := filepath.Glob("testdata/corpus/*.yaml")
	if err != nil {
		t.Fatalf("glob corpus: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no corpus files found under testdata/corpus/")
	}

	type bucketKey struct {
		expect string
		reason string
	}
	buckets := map[bucketKey]int{}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		var cf corpusFile
		if err := yaml.Unmarshal(data, &cf); err != nil {
			t.Fatalf("unmarshal %s: %v", file, err)
		}
		if len(cf.Entries) == 0 {
			t.Fatalf("no entries in %s", file)
		}

		base := filepath.Base(file)
		for i, entry := range cf.Entries {
			i, entry := i, entry
			name := fmt.Sprintf("%s#%d/%s", base, i, entry.Reason)
			t.Run(name, func(t *testing.T) {
				_, err := ParsePowerShell(entry.Command)
				switch entry.Expect {
				case "parses":
					if err != nil {
						t.Errorf("expected parse for %q (reason=%s): %v", entry.Command, entry.Reason, err)
					}
				case "rejects":
					if err == nil {
						t.Errorf("expected rejection for %q (reason=%s)", entry.Command, entry.Reason)
					}
				default:
					t.Fatalf("unknown expect %q for %q", entry.Expect, entry.Command)
				}
				buckets[bucketKey{entry.Expect, entry.Reason}]++
			})
		}
	}

	// Round-trip property: every accepted parse must reconstruct to a string
	// that re-parses to a Pipeline with the same command names and arg counts.
	// Catches bugs in render functions that would silently corrupt execution
	// (e.g., a calculated property's block getting quoted into a literal).
	t.Run("RoundTrip", func(t *testing.T) {
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("read %s: %v", file, err)
			}
			var cf corpusFile
			if err := yaml.Unmarshal(data, &cf); err != nil {
				continue
			}
			for _, entry := range cf.Entries {
				if entry.Expect != "parses" {
					continue
				}
				orig, err := ParsePowerShell(entry.Command)
				if err != nil {
					continue
				}
				reconstructed := renderPipelineForTest(orig)
				roundTripped, err := ParsePowerShell(reconstructed)
				if err != nil {
					t.Errorf("round-trip parse failed for %q -> %q: %v", entry.Command, reconstructed, err)
					continue
				}
				if len(orig.Segments) != len(roundTripped.Segments) {
					t.Errorf("round-trip segment count mismatch for %q: %d -> %d", entry.Command, len(orig.Segments), len(roundTripped.Segments))
					continue
				}
				for i := range orig.Segments {
					if orig.Segments[i].Command != roundTripped.Segments[i].Command {
						t.Errorf("round-trip command mismatch in %q: %q vs %q", entry.Command, orig.Segments[i].Command, roundTripped.Segments[i].Command)
					}
					if len(orig.Segments[i].Args) != len(roundTripped.Segments[i].Args) {
						t.Errorf("round-trip arg count mismatch in %q: seg=%s %d vs %d (orig=%v roundtrip=%v)", entry.Command, orig.Segments[i].Command, len(orig.Segments[i].Args), len(roundTripped.Segments[i].Args), orig.Segments[i].Args, roundTripped.Segments[i].Args)
					}
				}
			}
		}
	})

	// Reason summary, ordered so test -v output is stable.
	if testing.Verbose() {
		type row struct {
			expect string
			reason string
			count  int
		}
		rows := make([]row, 0, len(buckets))
		for k, v := range buckets {
			rows = append(rows, row{k.expect, k.reason, v})
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].expect != rows[j].expect {
				return rows[i].expect < rows[j].expect
			}
			return rows[i].reason < rows[j].reason
		})
		t.Logf("corpus summary:")
		for _, r := range rows {
			t.Logf("  %-8s %s (×%d)", r.expect, r.reason, r.count)
		}
	}
}
