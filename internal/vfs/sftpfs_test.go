// SPDX-License-Identifier: MIT

package vfs

import (
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestDialSSHHandshakeTimeout ensures that the SSH handshake honors the
// configured timeout. ssh.Dial only applies the timeout to the TCP connection,
// so a peer that accepts the connection and then stays silent used to block the
// handshake forever, hanging the SFTP filesystem and the caller.
func TestDialSSHHandshakeTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to create listener: %v", err)
	}
	defer listener.Close() //nolint:errcheck

	// Accept the connection but never send the SSH version banner.
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		accepted <- conn
	}()
	defer func() {
		select {
		case conn := <-accepted:
			conn.Close() //nolint:errcheck
		default:
		}
	}()

	const timeout = 500 * time.Millisecond
	config := &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
		Timeout:         timeout,
	}

	start := time.Now()
	_, err = dialSSH(listener.Addr().String(), config)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error for a peer that never completes the SSH handshake")
	}
	if elapsed > 10*timeout {
		t.Fatalf("handshake was not bounded by the configured timeout, took %s", elapsed)
	}
}

// TestDialSSHConnectionRefused ensures that a closed endpoint fails fast.
func TestDialSSHConnectionRefused(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to create listener: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close() //nolint:errcheck

	config := &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
		Timeout:         2 * time.Second,
	}
	if _, err := dialSSH(addr, config); err == nil {
		t.Fatal("expected an error dialing a closed endpoint")
	}
}
