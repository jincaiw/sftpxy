package ipfilter

import "testing"

func TestHandshakeCompatibility(t *testing.T) {
	if Handshake.MagicCookieKey != "SFTPXY_PLUGIN_IPFILTER" {
		t.Fatalf("Handshake.MagicCookieKey = %q", Handshake.MagicCookieKey)
	}
	if LegacyHandshake.MagicCookieKey != "SFTPGO_PLUGIN_IPFILTER" {
		t.Fatalf("LegacyHandshake.MagicCookieKey = %q", LegacyHandshake.MagicCookieKey)
	}
	if Handshake.MagicCookieValue != LegacyHandshake.MagicCookieValue {
		t.Fatalf("handshake values differ: %q vs %q", Handshake.MagicCookieValue, LegacyHandshake.MagicCookieValue)
	}
}
