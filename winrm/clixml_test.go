package winrm

import (
	"strings"
	"testing"
)

// Captured verbatim from a real 3DEXPERIENCE host (2026-08-21): two progress
// records for "Preparing modules for first use" on an exit-0 command.
const progressBlob = `#< CLIXML
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress" RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj><Obj S="progress" RefId="1"><TNRef RefId="0" /><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj></Objs>`

const errorBlob = `#< CLIXML
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><S S="Error">Get-Item : Cannot find path 'C:\missing'._x000D__x000A_</S><S S="Error">At line:1 char:1_x000D__x000A_</S><Obj S="progress" RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T></TN></Obj></Objs>`

func TestDecodeCLIXMLStderr_DropsProgressRecords(t *testing.T) {
	if got := DecodeCLIXMLStderr(progressBlob); got != "" {
		t.Errorf("progress-only blob should decode to empty stderr, got %q", got)
	}
}

func TestDecodeCLIXMLStderr_KeepsErrorText(t *testing.T) {
	got := DecodeCLIXMLStderr(errorBlob)
	if !strings.Contains(got, "Cannot find path 'C:\\missing'") {
		t.Errorf("error record text lost: %q", got)
	}
	if strings.Contains(got, "<Objs") || strings.Contains(got, "CLIXML") || strings.Contains(got, "_x000D_") {
		t.Errorf("decoded output still contains XML or escapes: %q", got)
	}
}

func TestDecodeCLIXMLStderr_PassthroughAndMalformed(t *testing.T) {
	plain := "plain stderr text\n"
	if got := DecodeCLIXMLStderr(plain); got != plain {
		t.Errorf("non-CLIXML stderr mangled: %q", got)
	}

	truncated := "#< CLIXML\n<Objs Version=\"1.1.0.1\"><S S=\"Error\">half a blob"
	if got := DecodeCLIXMLStderr(truncated); !strings.Contains(got, "half a blob") {
		t.Errorf("truncated blob should be preserved verbatim, got %q", got)
	}
}

func TestDecodeCLIXMLStderr_TextAroundBlobs(t *testing.T) {
	mixed := "real error line\n" + progressBlob + "\ntrailing text"
	got := DecodeCLIXMLStderr(mixed)
	if !strings.Contains(got, "real error line") || !strings.Contains(got, "trailing text") {
		t.Errorf("text outside blob lost: %q", got)
	}
	if strings.Contains(got, "CLIXML") {
		t.Errorf("blob survived decoding: %q", got)
	}
}
