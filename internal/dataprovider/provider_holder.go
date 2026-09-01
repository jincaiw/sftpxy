// SPDX-License-Identifier: MIT

package dataprovider

import (
	"sync"
	"sync/atomic"

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
	// config holds the active provider configuration as an immutable
	// snapshot. Swapping the whole configuration (tests re-initialize the
	// provider repeatedly) is done by storing a new pointer atomically, so
	// readers that already loaded the old snapshot keep a consistent view
	// without any lock: this removes the write/read race between setConfig
	// and background goroutines (e.g. protocol handlers, quota updater)
	// reading config fields through getConfig().
	config atomic.Pointer[Config]
	// argon2Params holds the active Argon2id hashing parameters. It is set once
	// during Initialize and read on every password hash verification.
	argon2Params *argon2id.Params
}

// holder is the single instance owning the active provider runtime state.
var holder = &providerHolder{}

// emptyConfig is returned by getConfig before the first initialization,
// preserving the previous zero-value semantics of the bare config variable.
var emptyConfig Config

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

// getConfig returns a pointer to the currently active configuration
// snapshot. The returned Config is immutable: it is never modified after
// being published, so callers can read its fields freely without holding any
// lock, even while a concurrent re-initialization publishes a new snapshot.
// Runtime mutations are not allowed; use updateConfig on the init path.
func (h *providerHolder) getConfig() *Config {
	if c := h.config.Load(); c != nil {
		return c
	}
	return &emptyConfig
}

// setConfig replaces the active configuration by publishing a new immutable
// snapshot atomically.
func (h *providerHolder) setConfig(c Config) {
	h.config.Store(&c)
}

// updateConfig applies f to a copy of the active configuration and publishes
// the result as a new snapshot. It exists for the single-threaded
// initialization path, which adjusts a few fields (backups path, resolved
// password, ...) after the initial setConfig; publishing a fresh snapshot
// keeps already-loaded readers consistent and race-free.
func (h *providerHolder) updateConfig(f func(c *Config)) {
	c := *h.config.Load()
	f(&c)
	h.config.Store(&c)
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
