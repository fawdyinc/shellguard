package control

import (
	"context"

	"github.com/fawdyinc/shellguard/server"
)

// CoreAdapter implements Handler by delegating to a server.Core instance.
type CoreAdapter struct {
	Core *server.Core
}

func (a *CoreAdapter) Connect(ctx context.Context, params ConnectParams) error {
	_, err := a.Core.Connect(ctx, server.ConnectInput{
		Host:         params.Host,
		User:         params.User,
		Port:         params.Port,
		IdentityFile: params.IdentityFile,
		Password:     params.Password,
		Passphrase:   params.Passphrase,
		Transport:    params.Transport,
		UseTLS:       params.UseTLS,
		Insecure:     params.Insecure,
		Command:      params.Command,
	})
	return err
}

func (a *CoreAdapter) Disconnect(ctx context.Context, params DisconnectParams) error {
	_, err := a.Core.Disconnect(ctx, server.DisconnectInput{
		Host: params.Host,
	})
	return err
}

func (a *CoreAdapter) ConnectedHosts() []string {
	return a.Core.ConnectedHostsSnapshot()
}
