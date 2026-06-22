// SPDX-License-Identifier: MIT

// Fully featured and highly configurable SFTP server with optional
// FTP/S and WebDAV support.
// For more details about features, installation, configuration and usage
// please refer to the README inside the source tree:
// https://github.com/jincaiw/sftpxy/blob/main/README.md
package main // import "github.com/jincaiw/sftpxy"

import (
	"github.com/jincaiw/sftpxy/v2/internal/cmd"
)

func main() {
	cmd.Execute()
}
