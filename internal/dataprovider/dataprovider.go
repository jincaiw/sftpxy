// Copyright (C) 2019 Nicola Murino
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

// Package dataprovider provides data access.
// It abstracts different data providers using a common API.
package dataprovider

// Provider is the composed contract every data backend must satisfy.
// Its definition lives in provider_iface.go, where it is assembled from
// domain-focused sub-interfaces (AuthStore, UserStore, FolderStore, ...).
// Keeping the decomposition in a dedicated file lets each capability be
// referenced and mocked independently in tests.
