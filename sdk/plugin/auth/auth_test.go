package auth

import "testing"

func TestHandshakeCompatibility(t *testing.T) {
	if Handshake.MagicCookieKey != "SFTPXY_PLUGIN_AUTH" {
		t.Fatalf("Handshake.MagicCookieKey = %q", Handshake.MagicCookieKey)
	}
	if LegacyHandshake.MagicCookieKey != "SFTPGO_PLUGIN_AUTH" {
		t.Fatalf("LegacyHandshake.MagicCookieKey = %q", LegacyHandshake.MagicCookieKey)
	}
	if Handshake.MagicCookieValue != LegacyHandshake.MagicCookieValue {
		t.Fatalf("handshake values differ: %q vs %q", Handshake.MagicCookieValue, LegacyHandshake.MagicCookieValue)
	}
}
