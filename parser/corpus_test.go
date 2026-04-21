package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
)

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
