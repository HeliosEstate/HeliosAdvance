// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Tests of Ctrl-U erasing the name over SSH, with the OpenSSH client and QA's own: every character
// removed, BS, space, BS written for each when the caller asked for a terminal.
package ssh_test

import (
	"strings"
	"testing"
)

func TestEraseLine(t *testing.T) {
	t.Parallel()
	erase := strings.Repeat("\b \b", 3)
	t.Run("When the caller sends Ctrl-U (0x15) while the name holds a character, the engine shall remove every character of the name.", func(t *testing.T) {
		t.Parallel()
		t.Run("the OpenSSH client with -tt, abc Ctrl-U d CR: three groups, then Hello d", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			result := runOpenSSH(t, program, openSSHCall{terminal: true, waitFor: prompt, typed: "abc\x15d\r"})
			expectCall(t, result, asked+"abc"+erase+"d\r\n"+helloTo("d"))
		})
		t.Run("the OpenSSH client with -T, abc Ctrl-U d CR: Hello d alone", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			result := runOpenSSH(t, program, openSSHCall{waitFor: prompt, typed: "abc\x15d\r"})
			expectCall(t, result, asked+helloTo("d"))
		})
		t.Run("QA's client with a pty-req, abc Ctrl-U d CR: three groups, then Hello d", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := callAtPrompt(t, program, true)
			client.sendData("abc\x15d\r")
			client.expectNameEnd(asked + "abc" + erase + "d\r\n" + helloTo("d"))
		})
		t.Run("QA's client with no pty-req, abc Ctrl-U d CR: Hello d alone", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			client := callAtPrompt(t, program, false)
			client.sendData("abc\x15d\r")
			client.expectNameEnd(asked + helloTo("d"))
		})
	})
	t.Run("If the caller sends BS, DEL, Ctrl-U, CR or LF while the name is empty, then the engine shall write nothing and keep waiting.", func(t *testing.T) {
		t.Parallel()
		t.Run("the OpenSSH client with -tt, Ctrl-U at the prompt, then a CR: the echo of a alone, Hello a", func(t *testing.T) {
			t.Parallel()
			program := startEngine(t)
			result := runOpenSSH(t, program, openSSHCall{terminal: true, waitFor: prompt, typed: "\x15a\r"})
			expectCall(t, result, asked+echoOf("a")+helloTo("a"))
		})
	})
}
