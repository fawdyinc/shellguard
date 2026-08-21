package winrm

import (
	"encoding/xml"
	"regexp"
	"strconv"
	"strings"
)

// PowerShell remoting serializes its non-stdout streams (progress, verbose,
// warning, error) as CLIXML blobs on stderr, prefixed with "#< CLIXML".
// Left undecoded, an exit-0 command whose only stderr is a "Preparing
// modules for first use" progress record looks like a failure to agents and
// tests, and real error records arrive as unreadable XML. Decode at the
// source so every consumer — agent, UI, logs — sees plain text.

const clixmlMarker = "#< CLIXML"

// clixmlEscapeRe matches PowerShell's _xHHHH_ character escapes (e.g.
// _x000D__x000A_ for CRLF).
var clixmlEscapeRe = regexp.MustCompile(`_x([0-9A-Fa-f]{4})_`)

type clixmlObjs struct {
	Nodes []clixmlNode `xml:",any"`
}

type clixmlNode struct {
	XMLName xml.Name
	Stream  string `xml:"S,attr"`
	Text    string `xml:",chardata"`
}

// DecodeCLIXMLStderr rewrites stderr from a remote PowerShell invocation into
// plain text. CLIXML blobs are parsed: progress and debug records are dropped
// entirely, and error/warning/verbose/info string records are decoded to
// their message text. Text outside CLIXML blobs passes through untouched, and
// a blob that fails to parse is preserved as-is rather than swallowed.
func DecodeCLIXMLStderr(stderr string) string {
	if !strings.Contains(stderr, clixmlMarker) {
		return stderr
	}

	var out strings.Builder
	rest := stderr
	for {
		start := strings.Index(rest, clixmlMarker)
		if start < 0 {
			out.WriteString(rest)
			break
		}
		out.WriteString(rest[:start])
		blob := rest[start:]

		open := strings.Index(blob, "<Objs")
		end := strings.Index(blob, "</Objs>")
		if open < 0 || end < 0 || end < open {
			// Truncated or malformed blob: keep it verbatim.
			out.WriteString(blob)
			break
		}
		end += len("</Objs>")

		decoded, ok := decodeClixmlDocument(blob[open:end])
		if !ok {
			out.WriteString(blob[:end])
		} else {
			out.WriteString(decoded)
		}
		rest = blob[end:]
	}

	return strings.TrimSpace(out.String())
}

// decodeClixmlDocument extracts the human-relevant text from one <Objs>
// document. Returns ok=false if the XML does not parse.
func decodeClixmlDocument(doc string) (string, bool) {
	var objs clixmlObjs
	if err := xml.Unmarshal([]byte(doc), &objs); err != nil {
		return "", false
	}

	var lines []string
	for _, node := range objs.Nodes {
		// Progress records (<Obj S="progress">) and debug chatter carry no
		// diagnostic value; drop them. Only string records from the error,
		// warning, verbose, and information streams are kept.
		if node.XMLName.Local != "S" {
			continue
		}
		switch node.Stream {
		case "Error", "Warning", "Verbose", "Info", "Information":
			text := strings.TrimSpace(decodeClixmlEscapes(node.Text))
			if text != "" {
				lines = append(lines, text)
			}
		}
	}
	return strings.Join(lines, "\n"), true
}

// decodeClixmlEscapes rewrites _xHHHH_ escapes to their characters, then
// normalizes CRLF to LF.
func decodeClixmlEscapes(s string) string {
	s = clixmlEscapeRe.ReplaceAllStringFunc(s, func(m string) string {
		code, err := strconv.ParseUint(m[2:6], 16, 32)
		if err != nil {
			return m
		}
		return string(rune(code))
	})
	return strings.ReplaceAll(s, "\r\n", "\n")
}
