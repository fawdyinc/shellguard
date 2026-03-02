// Package control provides a JSON-over-TCP API for managing ShellGuard
// connections without going through the MCP/agent layer.
package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"sync"
)

// Request is the envelope sent by a client over the control socket.
type Request struct {
	Command string          `json:"command"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is the envelope sent back to the client.
type Response struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}

// ConnectParams are the parameters for the "connect" command.
type ConnectParams struct {
	Host         string `json:"host"`
	User         string `json:"user,omitempty"`
	Port         int    `json:"port,omitempty"`
	IdentityFile string `json:"identity_file,omitempty"`
}

// DisconnectParams are the parameters for the "disconnect" command.
type DisconnectParams struct {
	Host string `json:"host"`
}

// StatusData is returned by the "status" command.
type StatusData struct {
	ConnectedHosts []string `json:"connected_hosts"`
}

// Handler is the interface that the control socket server dispatches to.
type Handler interface {
	Connect(ctx context.Context, params ConnectParams) error
	Disconnect(ctx context.Context, params DisconnectParams) error
	ConnectedHosts() []string
}

// Server listens on a Unix socket and dispatches JSON requests to a Handler.
type Server struct {
	listener net.Listener
	handler  Handler
	logger   *slog.Logger

	wg sync.WaitGroup
}

// ListenAndServe starts the control server on TCP localhost. It writes the
// resolved host:port to addrPath so clients can discover it. It blocks until
// ctx is cancelled, then cleans up the addr file.
func ListenAndServe(ctx context.Context, addrPath string, handler Handler, logger *slog.Logger) error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}

	resolvedAddr := ln.Addr().String()
	if err := os.WriteFile(addrPath, []byte(resolvedAddr), 0600); err != nil {
		_ = ln.Close()
		return err
	}

	s := &Server{
		listener: ln,
		handler:  handler,
		logger:   logger,
	}

	// Shut down when context is cancelled.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	logger.Info("control server listening", "addr", resolvedAddr, "addrFile", addrPath)

	for {
		conn, err := ln.Accept()
		if err != nil {
			// Expected when listener is closed during shutdown.
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				break
			}
			logger.Warn("control server accept error", "error", err)
			continue
		}
		s.wg.Add(1)
		go s.handleConn(ctx, conn)
	}

	s.wg.Wait()
	_ = os.Remove(addrPath)
	logger.Info("control server stopped")
	return nil
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer s.wg.Done()
	defer func() { _ = conn.Close() }()

	scanner := bufio.NewScanner(conn)
	// Allow up to 1 MB per line.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			s.writeResponse(conn, Response{Error: "invalid JSON: " + err.Error()})
			continue
		}

		resp := s.dispatch(ctx, req)
		s.writeResponse(conn, resp)
	}
}

func (s *Server) dispatch(ctx context.Context, req Request) Response {
	switch req.Command {
	case "connect":
		var params ConnectParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return Response{Error: "invalid connect params: " + err.Error()}
		}
		if err := s.handler.Connect(ctx, params); err != nil {
			return Response{Error: err.Error()}
		}
		data, _ := json.Marshal(map[string]string{
			"host":    params.Host,
			"message": "Connected to " + params.Host,
		})
		return Response{OK: true, Data: data}

	case "disconnect":
		var params DisconnectParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return Response{Error: "invalid disconnect params: " + err.Error()}
		}
		if err := s.handler.Disconnect(ctx, params); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{OK: true}

	case "status":
		hosts := s.handler.ConnectedHosts()
		data, _ := json.Marshal(StatusData{ConnectedHosts: hosts})
		return Response{OK: true, Data: data}

	default:
		return Response{Error: "unknown command: " + req.Command}
	}
}

func (s *Server) writeResponse(conn net.Conn, resp Response) {
	line, err := json.Marshal(resp)
	if err != nil {
		s.logger.Error("control socket marshal error", "error", err)
		return
	}
	line = append(line, '\n')
	if _, err := conn.Write(line); err != nil {
		s.logger.Debug("control socket write error", "error", err)
	}
}
