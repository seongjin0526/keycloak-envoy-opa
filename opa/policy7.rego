package http.authz
import future.keywords.if

default allow := {"allowed": false, "http_status": 403, "body": "forbidden"}

# 입력 헬퍼
method() := m if { m := input.attributes.request.http.method }

payload() := p if {
  raw := input.attributes.request.http.headers["x-jwt-payload"]
  p := json.unmarshal(raw)
}

has_realm_role(r) if {
  p := payload()
  some i
  p.realm_access.roles[i] == r
}

# --- GET → reader 허용
allow := {"allowed": true, "headers": {"x-opa": "ok", "x-opa-reason": "GET ok: reader"}} if {
  upper(method()) == "GET"
  has_realm_role("reader")
}

# --- POST → writer 허용
allow := {"allowed": true, "headers": {"x-opa": "ok", "x-opa-reason": "POST ok: writer"}} if {
  upper(method()) == "POST"
  has_realm_role("writer")
}

# payload 자체가 없으면 401
allow := {"allowed": false, "http_status": 401, "body": "missing jwt payload"} if {
  not input.attributes.request.http.headers["x-jwt-payload"]
}

