// SPDX-License-Identifier: MIT

package httpd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jincaiw/sftpxy/v2/internal/util"
)

func TestFlashMessages(t *testing.T) {
	rr := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/url", nil)
	require.NoError(t, err)
	message := flashMessage{
		ErrorString: "error",
		I18nMessage: util.I18nChangePwdTitle,
	}
	setFlashMessage(rr, req, message)
	value, err := json.Marshal(message)
	assert.NoError(t, err)
	req.Header.Set("Cookie", fmt.Sprintf("%v=%v", flashCookieName, base64.URLEncoding.EncodeToString(value)))
	msg := getFlashMessage(rr, req)
	assert.Equal(t, message, msg)
	assert.Equal(t, util.I18nChangePwdTitle, msg.getI18nError().Message)
	req.Header.Set("Cookie", fmt.Sprintf("%v=%v", flashCookieName, "a"))
	msg = getFlashMessage(rr, req)
	assert.Empty(t, msg)
	req.Header.Set("Cookie", fmt.Sprintf("%v=%v", flashCookieName, "YQ=="))
	msg = getFlashMessage(rr, req)
	assert.Empty(t, msg)
}
