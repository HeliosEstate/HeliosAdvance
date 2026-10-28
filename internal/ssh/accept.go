// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package ssh

import (
	"context"
	"net"

	"github.com/heliosestate/heliosadvance/internal/timeup"
	cryptossh "golang.org/x/crypto/ssh"
)

// serverConfig is made per call. The library adds the strict-exchange marker and uses strict
// exchange when the caller offers it, sends compression none, offers the host key as ssh-ed25519
// alone, and ends the handshake without a reply when a caller tries a sign-in method but none,
// since none is left to offer.
func serverConfig(key *HostKey) *cryptossh.ServerConfig {
	config := &cryptossh.ServerConfig{
		Config: cryptossh.Config{
			KeyExchanges: []string{
				"mlkem768x25519-sha256",
				cryptossh.KeyExchangeCurve25519,
				"curve25519-sha256@libssh.org",
			},
			Ciphers: []string{
				cryptossh.CipherChaCha20Poly1305,
				cryptossh.CipherAES256GCM,
				cryptossh.CipherAES128GCM,
			},
			MACs: []string{cryptossh.HMACSHA256ETM},
		},
		PublicKeyAuthAlgorithms: []string{cryptossh.KeyAlgoED25519},
		NoClientAuth:            true,
		ServerVersion:           VersionLine,
	}
	config.AddHostKey(key.state.signer)
	return config
}

func accept(ctx context.Context, tcp *net.TCPConn, key *HostKey) (*Channel, error) {
	if cause := timeup.Ended(ctx); cause != nil {
		return nil, deadlineEnded(cause)
	}
	if tcp == nil || key == nil || key.state.signer == nil {
		return nil, ErrConnectionFailed
	}
	shared := newConnection()
	release := timeup.WakeOnEnd(ctx, tcp)
	channel, err := open(ctx, tcp, shared, key)
	release()
	// The context's deadline may have passed by the clock before the context reports it, so the
	// call is judged after the wake is released, whatever it returned.
	if cause := timeup.Ended(ctx); cause != nil {
		// The release can stop a wake that had not begun, and the library goes on answering the
		// caller until the socket's deadlines are past, so they are set here as well.
		//nolint:errcheck // a socket that cannot be set is failing, and its end reaches every call
		timeup.Wake(tcp)
		return nil, deadlineEnded(cause)
	}
	if err != nil {
		return nil, err
	}
	return channel, nil
}

// open does the handshake and waits for the shell. Every error is the package's own, never the
// library's, whose text can quote what the caller sent.
func open(ctx context.Context, tcp *net.TCPConn, shared *connection, key *HostKey) (*Channel, error) {
	server, channels, requests, err := cryptossh.NewServerConn(tcp, serverConfig(key))
	if err != nil {
		return nil, ErrNoShell
	}
	sessions := make(chan cryptossh.NewChannel, 1)
	go cryptossh.DiscardRequests(requests)
	go shared.serveChannels(server, channels, sessions)

	var session cryptossh.NewChannel
	select {
	case session = <-sessions:
	case <-shared.ended:
		return nil, ErrNoShell
	case <-ctx.Done():
		return nil, deadlineEnded(timeup.Ended(ctx))
	}
	library, sessionRequests, err := session.Accept()
	if err != nil {
		return nil, ErrNoShell
	}
	channel := &Channel{state: newChannelState(library, shared)}
	state := &channel.state
	go state.readLoop()
	go state.writeLoop()
	go state.drainExtended()
	// The requests are drained for as long as the channel lives, even after an error here: the
	// library's reader blocks when the queue is full.
	defer func() { go refuseRequests(sessionRequests) }()

	if err := channel.awaitShell(ctx, sessionRequests); err != nil {
		return nil, err
	}
	return channel, nil
}

// serveChannels hands the first session channel to Accept undecided and refuses every other,
// then takes the library's Wait as the connection's end, so that no call waits on a connection
// that has gone.
func (connection *connection) serveChannels(
	server *cryptossh.ServerConn, channels <-chan cryptossh.NewChannel, sessions chan<- cryptossh.NewChannel,
) {
	first := true
	for newChannel := range channels {
		isSession := newChannel.ChannelType() == "session"
		if isSession && first {
			first = false
			sessions <- newChannel
			continue
		}
		reason := cryptossh.UnknownChannelType
		if isSession {
			reason = cryptossh.Prohibited
		}
		// A refusal that cannot be sent means the connection is failing, and its end reaches every
		// call through ended.
		//nolint:errcheck // nothing else is told of a refusal that cannot be sent
		newChannel.Reject(reason, "")
	}
	//nolint:errcheck // no result reads how the connection ended
	server.Wait()
	close(connection.ended)
}

// refuseRequests answers every request with failure until the library ends the channel. A reply
// that cannot be sent means the connection is failing, which every call learns from its end; the
// draining goes on, since the library's reader blocks on a full queue.
func refuseRequests(requests <-chan *cryptossh.Request) {
	for request := range requests {
		//nolint:errcheck // a reply that cannot be sent means the connection is ending
		request.Reply(false, nil)
	}
}

// awaitShell answers the channel's requests until the first shell. It reads nothing: end of file
// before the shell changes nothing, and a read kept waiting through it would store the end, so
// that RecvChar after the shell would meet it before the wait that writes out the echo. The
// library closes the session's requests when the connection ends and keeps what was queued, so a
// shell queued just before that end is still read; it is answered only if it asked for no reply,
// since a reply cannot be sent on an ended connection and answer then returns ErrNoShell.
func (channel *Channel) awaitShell(ctx context.Context, requests <-chan *cryptossh.Request) error {
	for {
		select {
		case request, open := <-requests:
			if !open {
				return ErrNoShell
			}
			shell, err := channel.answer(request)
			if err != nil {
				return err
			}
			if shell {
				return nil
			}
		case <-ctx.Done():
			return deadlineEnded(timeup.Ended(ctx))
		}
	}
}

// answer replies to one request before the shell. It never reads the payload: nothing a pty-req
// carries is kept.
func (channel *Channel) answer(request *cryptossh.Request) (shell bool, err error) {
	state := &channel.state
	accepted := request.Type == "pty-req" || request.Type == "shell"
	if request.Reply(accepted, nil) != nil {
		return false, ErrNoShell
	}
	switch request.Type {
	case "pty-req":
		state.echo = true
	case "shell":
		return true, nil
	}
	return false, nil
}
