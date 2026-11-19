// SPDX-License-Identifier: MIT

package httpd

import "testing"

// newTestBinding returns a minimal valid binding that enables both web UIs.
func newTestBinding() Binding {
	return Binding{
		Port:            30080,
		EnableWebAdmin:  true,
		EnableWebClient: true,
		EnableRESTAPI:   true,
		MinTLSVersion:   12,
	}
}

// TestCheckBindingsAppliesDefaultsToSlice guards the regression that made every
// WebAdmin/WebClient page render without a single stylesheet.
//
// Conf.Initialize validates the bindings through checkBindings and then starts
// the servers from the same slice. check() has a pointer receiver and stores the
// branding defaults on the receiver, so the loop must run over the elements
// themselves; iterating by value applied the defaults to a copy, the servers
// started from the untouched slice, and the templates rendered no <link> at all.
func TestCheckBindingsAppliesDefaultsToSlice(t *testing.T) {
	conf := Conf{Bindings: []Binding{newTestBinding()}}

	if err := conf.checkBindings(); err != nil {
		t.Fatalf("checkBindings() failed: %v", err)
	}

	admin := conf.Bindings[0].Branding.WebAdmin
	if len(admin.DefaultCSS) == 0 {
		t.Fatalf("DefaultCSS missing from the binding: got %v, WebAdmin would render unstyled", admin.DefaultCSS)
	}
	if admin.LogoPath == "" {
		t.Fatal("LogoPath missing from the binding, WebAdmin would render a broken logo")
	}
	if admin.FaviconPath == "" {
		t.Fatal("FaviconPath missing from the binding")
	}
	if admin.Name != "SFTPxy WebAdmin" {
		t.Fatalf("unexpected WebAdmin name %q", admin.Name)
	}
	if client := conf.Bindings[0].Branding.WebClient; len(client.DefaultCSS) == 0 {
		t.Fatal("DefaultCSS missing from the WebClient binding")
	}
}

// TestServerRendersStylesheets asserts what the templates actually read: the
// server built from the defaulted binding must expose the default stylesheets
// through the branding accessor used at render time.
func TestServerRendersStylesheets(t *testing.T) {
	conf := Conf{Bindings: []Binding{newTestBinding()}}
	if err := conf.checkBindings(); err != nil {
		t.Fatalf("checkBindings() failed: %v", err)
	}

	// Initialize hands each valid binding to newHttpdServer by value; reproduce
	// that hand-off so the assertion covers the real path.
	s := newHttpdServer(conf.Bindings[0], "", "", CorsConfig{}, "")

	adminCSS := s.binding.webAdminBranding().DefaultCSS
	if len(adminCSS) == 0 {
		t.Fatal("WebAdmin would render without stylesheets: DefaultCSS is empty")
	}
	clientCSS := s.binding.webClientBranding().DefaultCSS
	if len(clientCSS) == 0 {
		t.Fatal("WebClient would render without stylesheets: DefaultCSS is empty")
	}
	if logo := s.binding.webAdminBranding().LogoPath; logo == "" {
		t.Fatal("WebAdmin would render a broken logo: LogoPath is empty")
	}
}

// TestCheckBindingsSkipsInvalidBindings ensures the extracted helper keeps the
// original behaviour of ignoring bindings that are not valid.
func TestCheckBindingsSkipsInvalidBindings(t *testing.T) {
	conf := Conf{Bindings: []Binding{{Port: 0}}}

	if err := conf.checkBindings(); err != nil {
		t.Fatalf("checkBindings() should ignore invalid bindings, got error: %v", err)
	}
	if len(conf.Bindings[0].Branding.WebAdmin.DefaultCSS) != 0 {
		t.Fatal("invalid binding should not be defaulted")
	}
}
