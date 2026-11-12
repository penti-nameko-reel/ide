package idp

import "embed"

//go:embed web/index.html web/login.html web/admin.html
var WebFS embed.FS
