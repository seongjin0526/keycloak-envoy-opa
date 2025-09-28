package http.authz
import future.keywords.if

default allow := {"allowed": true, "headers": {"x-opa": "always-allow"}}

