package http.authz
import future.keywords.if

default allow := {"allowed": false, "http_status": 403, "body": "forbidden"}

# --- dynamic metadata 접근 (camel/snake 모두 시도) ---
get_md() := m if {
  # Envoy ext_authz v3에서 흔히 보이는 camelCase
  m := input.attributes.metadataContext.filter_metadata["envoy.filters.http.jwt_authn"]
} else := m if {
  # (환경에 따라) snake_case 로 들어오는 경우도 커버
  m := input.attributes.metadata_context.filter_metadata["envoy.filters.http.jwt_authn"]
}

# --- JWT payload 로딩: object / string(JSON) 모두 지원 ---
get_payload() := p if {
  md := get_md()
  v := md["jwt"]
  is_object(v)
  p := v
} else := p if {
  md := get_md()
  v := md["jwt"]
  not is_object(v)
  p := json.unmarshal(v)
}

method() := m if { m := input.attributes.request.http.method }

iss_ok if {
  p := get_payload()
  endswith(p.iss, "/realms/demo")
}

exp_ok if {
  p := get_payload()
  time.now_ns()/1000000000 < p.exp
}

has_realm_role(r) if {
  p := get_payload()
  some i
  p.realm_access.roles[i] == r
}

# --- payload 없으면 401 (헤더가 아니라 메타데이터를 기준으로 판단) ---
allow := {"allowed": false, "http_status": 401, "body": "missing jwt payload"} if {
  md := get_md()
  not md["jwt"]
}

# --- RBAC ---
allow := {"allowed": true, "headers": {"x-opa": "ok", "x-opa-reason": "GET ok: reader"}} if {
  iss_ok
  exp_ok
  upper(method()) == "GET"
  has_realm_role("reader")
}

allow := {"allowed": true, "headers": {"x-opa": "ok", "x-opa-reason": "POST ok: writer"}} if {
  iss_ok
  exp_ok
  upper(method()) == "POST"
  has_realm_role("writer")
}

