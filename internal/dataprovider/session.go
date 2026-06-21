// SPDX-License-Identifier: MIT

package dataprovider

import (
	"errors"
	"fmt"
)

// SessionType defines the supported session types
type SessionType int

// Supported session types
const (
	SessionTypeOIDCAuth SessionType = iota + 1
	SessionTypeOIDCToken
	SessionTypeResetCode
	SessionTypeOAuth2Auth
	SessionTypeInvalidToken
	SessionTypeWebTask
)

// Session defines a shared session persisted in the data provider
type Session struct {
	Key       string
	Data      any
	Type      SessionType
	Timestamp int64
}

func (s *Session) validate() error {
	if s.Key == "" {
		return errors.New("unable to save a session with an empty key")
	}
	if s.Type < SessionTypeOIDCAuth || s.Type > SessionTypeWebTask {
		return fmt.Errorf("invalid session type: %v", s.Type)
	}
	return nil
}
