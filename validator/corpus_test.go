package validator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fawdyinc/shellguard/parser"
	"gopkg.in/yaml.v3"
)

type corpusEntry struct {
	Command       string `yaml:"command"`
	Expect        string `yaml:"expect"`
	Reason        string `yaml:"reason"`
	ErrorContains string `yaml:"error_contains"`
}

type corpusFile struct {
	Entries []corpusEntry `yaml:"entries"`
}

// TestCorpus runs recorded session commands through parse + validate. Unlike
// the parser corpus, a passing entry here means the command would actually be
// permitted to execute.
func TestCorpus(t *testing.T) {
	paths, err := filepath.Glob("testdata/corpus/*.yaml")
	if err != nil {
		t.Fatalf("glob corpus: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no corpus files found")
	}

	registry := testRegistry(t)

	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var cf corpusFile
		if err := yaml.Unmarshal(b, &cf); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		// A misspelled or emptied `entries:` key would otherwise unmarshal to
		// zero entries and this test would report green having asserted
		// nothing at all.
		if len(cf.Entries) == 0 {
			t.Fatalf("%s: yielded zero entries - check the entries: key", path)
		}

		for _, e := range cf.Entries {
			t.Run(e.Reason, func(t *testing.T) {
				p, parseErr := parser.ParsePowerShell(e.Command)
				var err error
				if parseErr != nil {
					err = parseErr
				} else {
					err = ValidatePipeline(p, registry)
				}

				switch e.Expect {
				case "accepts":
					if err != nil {
						t.Errorf("%q: expected accept, got %v", e.Command, err)
					}
				case "rejects":
					if err == nil {
						t.Errorf("%q: expected reject, got nil", e.Command)
					}
					// error_contains proves the rejection happens for the
					// documented reason, not merely that *some* layer (parser
					// or validator) happened to reject the command.
					if err != nil && e.ErrorContains != "" && !strings.Contains(err.Error(), e.ErrorContains) {
						t.Errorf("%q: expected error to contain %q, got %v", e.Command, e.ErrorContains, err)
					}
				default:
					t.Fatalf("%q: unknown expect value %q", e.Command, e.Expect)
				}
			})
		}
	}
}
