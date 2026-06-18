// Copyright (C) 2024 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package dataprovider

import (
	"sync"

	"github.com/alexedwards/argon2id"
)

// providerHolder centralizes the package's mutable runtime state that was
// previously scattered as bare package-level variables (provider, config,
// argon2Params, etc.). Consolidating it here:
//   - serializes writes via a mutex, fixing the latent data race where the
//     five initialize*Provider functions assigned the bare `provider` global
//     with no synchronization;
//   - gives a single, auditable assignment surface (set* methods);
//   - is the natural injection point for future dependency-injection and for
//     unit tests that want to swap the active backend or config.
//
// The exported package-level facade functions (AddUser, GetUser, ...) are
// preserved unchanged, so every external caller keeps working; they now reach
// the backend through the holder's accessors.
type providerHolder struct {
	mu sync.RWMutex

	provider Provider
	config   Config
	// argon2Params holds the active Argon2id hashing parameters. It is set once
	// during Initialize and read on every password hash verification.
	argon2Params *argon2id.Params
}

// holder is the single instance owning the active provider runtime state.
var holder = &providerHolder{}

// getProvider returns the active Provider under a read lock. Callers must not
// retain the returned value across long-lived operations expecting it to stay
// current; instead re-invoke this accessor.
func (h *providerHolder) getProvider() Provider {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.provider
}

// setProvider replaces the active backend under a write lock. Called only from
// the initialize*Provider entrypoints during Initialize.
func (h *providerHolder) setProvider(p Provider) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.provider = p
}

// getConfig returns a pointer to the active provider configuration under a
// read lock. Config is a large struct (dozens of scalar fields plus nested
// Actions/Defender/RateLimiters/Node sub-structs), so returning a pointer
// avoids a full copy on every access — this matters on hot paths such as
// quota checks which read config fields on each transfer.
//
// The pointer targets the holder's stored config. Callers must treat it as
// read-only: mutating it is NOT serialized and must not happen at runtime.
// Legitimate mutations (all confined to the single-threaded Initialize path)
// go through setConfig or an explicit, documented in-place edit during init.
func (h *providerHolder) getConfig() *Config {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return &h.config
}

// setConfig replaces the active configuration under a write lock.
func (h *providerHolder) setConfig(c Config) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.config = c
}

// getArgon2Params returns the active Argon2id parameters under a read lock.
func (h *providerHolder) getArgon2Params() *argon2id.Params {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.argon2Params
}

// setArgon2Params replaces the active Argon2id parameters under a write lock.
func (h *providerHolder) setArgon2Params(p *argon2id.Params) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.argon2Params = p
}
