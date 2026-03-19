package winrm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const (
	// chunkSize is the size of each file read/write chunk.
	// Kept well under WinRM's default MaxEnvelopeSizekb (500KB).
	chunkSize = 256 * 1024

	// smallFileThreshold is the max file size for single-call reads.
	smallFileThreshold = 1 * 1024 * 1024
)

// fileStatResult holds the JSON output from Get-Item.
type fileStatResult struct {
	Name          string `json:"Name"`
	Length        int64  `json:"Length"`
	LastWriteTime string `json:"LastWriteTime"`
	IsDirectory   bool   `json:"PSIsContainer"`
}

// WinRMFileClient implements ssh.SFTPClient using PowerShell commands over WinRM.
type WinRMFileClient struct {
	client *winrmClient
}

// NewWinRMFileClient creates a new file client using an existing WinRM connection.
func NewWinRMFileClient(client *winrmClient) *WinRMFileClient {
	return &WinRMFileClient{client: client}
}

// Stat returns file information via PowerShell Get-Item.
func (f *WinRMFileClient) Stat(path string) (os.FileInfo, error) {
	psCmd := fmt.Sprintf("Get-Item -LiteralPath '%s' | Select-Object Name,Length,LastWriteTime,PSIsContainer | ConvertTo-Json",
		psEscapeSingleQuote(path))

	result, err := f.client.Execute(context.Background(), WrapForWinRM(psCmd), 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("stat %s: %s", path, strings.TrimSpace(result.Stderr))
	}

	var stat fileStatResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(result.Stdout)), &stat); err != nil {
		return nil, fmt.Errorf("stat %s: parse output: %w", path, err)
	}

	return &winrmFileInfo{
		name:  stat.Name,
		size:  stat.Length,
		isDir: stat.IsDirectory,
	}, nil
}

// Open reads a remote file and returns its content as a ReadCloser.
// Uses chunked reads for files larger than smallFileThreshold.
func (f *WinRMFileClient) Open(path string) (io.ReadCloser, error) {
	info, err := f.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("cannot open directory: %s", path)
	}

	escapedPath := psEscapeSingleQuote(path)

	if info.Size() < smallFileThreshold {
		psCmd := fmt.Sprintf("[Convert]::ToBase64String([IO.File]::ReadAllBytes('%s'))", escapedPath)
		result, err := f.client.Execute(context.Background(), WrapForWinRM(psCmd), 60*time.Second)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		if result.ExitCode != 0 {
			return nil, fmt.Errorf("read %s: %s", path, strings.TrimSpace(result.Stderr))
		}

		data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(result.Stdout))
		if err != nil {
			return nil, fmt.Errorf("read %s: decode: %w", path, err)
		}
		return io.NopCloser(bytes.NewReader(data)), nil
	}

	// Chunked read for large files.
	var buf bytes.Buffer
	fileSize := info.Size()
	for offset := int64(0); offset < fileSize; offset += chunkSize {
		readLen := int64(chunkSize)
		if offset+readLen > fileSize {
			readLen = fileSize - offset
		}

		psCmd := fmt.Sprintf(
			"$fs = [IO.File]::OpenRead('%s'); $fs.Seek(%d, 'Begin') | Out-Null; "+
				"$buf = New-Object byte[] %d; $n = $fs.Read($buf, 0, %d); $fs.Close(); "+
				"[Convert]::ToBase64String($buf, 0, $n)",
			escapedPath, offset, readLen, readLen)

		result, err := f.client.Execute(context.Background(), WrapForWinRM(psCmd), 60*time.Second)
		if err != nil {
			return nil, fmt.Errorf("read chunk at offset %d of %s: %w", offset, path, err)
		}
		if result.ExitCode != 0 {
			return nil, fmt.Errorf("read chunk at offset %d of %s: %s", offset, path, strings.TrimSpace(result.Stderr))
		}

		chunk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(result.Stdout))
		if err != nil {
			return nil, fmt.Errorf("read chunk at offset %d of %s: decode: %w", offset, path, err)
		}
		buf.Write(chunk)
	}

	return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
}

// Create writes a file on the remote system via chunked base64 writes.
func (f *WinRMFileClient) Create(path string) (io.WriteCloser, error) {
	return &winrmWriter{client: f.client, path: path}, nil
}

// MkdirAll creates a directory and all parents on the remote system.
func (f *WinRMFileClient) MkdirAll(path string) error {
	psCmd := fmt.Sprintf("New-Item -ItemType Directory -Force -Path '%s' | Out-Null", psEscapeSingleQuote(path))
	result, err := f.client.Execute(context.Background(), WrapForWinRM(psCmd), 30*time.Second)
	if err != nil {
		return fmt.Errorf("mkdir %s: %w", path, err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("mkdir %s: %s", path, strings.TrimSpace(result.Stderr))
	}
	return nil
}

// Chmod is a no-op on Windows (ACLs are not managed this way).
func (f *WinRMFileClient) Chmod(_ string, _ os.FileMode) error {
	return nil
}

// Close is a no-op since WinRM file operations are stateless.
func (f *WinRMFileClient) Close() error {
	return nil
}

// winrmWriter accumulates write data and flushes to remote on Close.
type winrmWriter struct {
	client *winrmClient
	path   string
	buf    bytes.Buffer
}

func (w *winrmWriter) Write(p []byte) (int, error) {
	return w.buf.Write(p)
}

func (w *winrmWriter) Close() error {
	data := w.buf.Bytes()
	escapedPath := psEscapeSingleQuote(w.path)

	// Clear the file first.
	psCmd := fmt.Sprintf("[IO.File]::WriteAllBytes('%s', [byte[]]@())", escapedPath)
	result, err := w.client.Execute(context.Background(), WrapForWinRM(psCmd), 30*time.Second)
	if err != nil {
		return fmt.Errorf("create %s: %w", w.path, err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("create %s: %s", w.path, strings.TrimSpace(result.Stderr))
	}

	// Write in chunks.
	for offset := 0; offset < len(data); offset += chunkSize {
		end := offset + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[offset:end]
		b64 := base64.StdEncoding.EncodeToString(chunk)

		psCmd = fmt.Sprintf(
			"$bytes = [Convert]::FromBase64String('%s'); "+
				"$fs = [IO.File]::OpenWrite('%s'); $fs.Seek(0, 'End') | Out-Null; "+
				"$fs.Write($bytes, 0, $bytes.Length); $fs.Close()",
			b64, escapedPath)

		result, err = w.client.Execute(context.Background(), WrapForWinRM(psCmd), 60*time.Second)
		if err != nil {
			return fmt.Errorf("write chunk to %s: %w", w.path, err)
		}
		if result.ExitCode != 0 {
			return fmt.Errorf("write chunk to %s: %s", w.path, strings.TrimSpace(result.Stderr))
		}
	}

	return nil
}

// winrmFileInfo implements os.FileInfo.
type winrmFileInfo struct {
	name  string
	size  int64
	isDir bool
}

func (fi *winrmFileInfo) Name() string      { return fi.name }
func (fi *winrmFileInfo) Size() int64        { return fi.size }
func (fi *winrmFileInfo) IsDir() bool        { return fi.isDir }
func (fi *winrmFileInfo) Mode() os.FileMode  { return 0o644 }
func (fi *winrmFileInfo) ModTime() time.Time { return time.Time{} }
func (fi *winrmFileInfo) Sys() any           { return nil }

// psEscapeSingleQuote escapes single quotes for use inside PowerShell
// single-quoted strings by doubling them.
func psEscapeSingleQuote(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
