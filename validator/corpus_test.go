package validator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fawdyinc/shellguard/parser"
	"gopkg.in/yaml.v3"
)

type corpusEntry struct {
	Command string `yaml:"command"`
	Expect  string `yaml:"expect"`
	Reason  string `yaml:"reason"`
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
				default:
					t.Fatalf("%q: unknown expect value %q", e.Command, e.Expect)
				}
			})
		}
	}
}
