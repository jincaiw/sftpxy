// SPDX-License-Identifier: MIT

// Package dataprovider provides data access.
// It abstracts different data providers using a common API.
package dataprovider

// Provider is the composed contract every data backend must satisfy.
// Its definition lives in provider_iface.go, where it is assembled from
// domain-focused sub-interfaces (AuthStore, UserStore, FolderStore, ...).
// Keeping the decomposition in a dedicated file lets each capability be
// referenced and mocked independently in tests.
