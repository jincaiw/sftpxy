// SPDX-License-Identifier: MIT

//go:build unixcrypt && cgo

package dataprovider

import (
	"strings"

	"github.com/amoghe/go-crypt"

	"github.com/jincaiw/sftpxy/v2/internal/version"
)

func init() {
	version.AddFeature("+unixcrypt")
}

func compareYescryptPassword(hashedPwd, plainPwd string) (bool, error) {
	lastIdx := strings.LastIndex(hashedPwd, "$")
	pwd, err := crypt.Crypt(plainPwd, hashedPwd[:lastIdx+1])
	if err != nil {
		return false, err
	}
	return pwd == hashedPwd, nil
}
