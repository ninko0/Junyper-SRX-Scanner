// Package web embeds the static assets (index.html, style.css, app.js)
// into the binary via the stdlib's `embed` — avoids having to manage a
// separate volume for the assets in production (cf task 06, deliverables).
package web

import "embed"

//go:embed index.html style.css app.js
var Assets embed.FS
