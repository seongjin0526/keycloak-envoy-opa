package http.authz
import future.keywords.if

# 기본 거부
default allow := {"allowed": false, "http_status": 403, "body": "forbidden"}

# --- 입력 헬퍼 (v1 함수 규칙) ---
method() := m if {
  m := input.attributes.request.http.method
}

get_payload() := p if {
  raw := input.attributes.request.http.headers["x-jwt-payload"]
  p := json.unmarshal(raw)
}

# --- 검증 ---
iss_ok if {
  p := get_payload()
  endswith(p.iss, "/realms/demo")        # 내부/외부 호스트 차이 흡수
}

exp_ok if {
  p := get_payload()
  time.now_ns()/1000000000 < p.exp
}

has_realm_role(role) if {
  p := get_payload()
  some i
  p.realm_access.roles[i] == role
}

# --- 명확한 401: JWT payload 자체가 없을 때 ---
allow := {"allowed": false, "http_status": 401, "body": "missing jwt payload"} if {
  not input.attributes.request.http.headers["x-jwt-payload"]
}

# --- RBAC ---
# GET → reader 허용
allow := {"allowed": true, "headers": {"x-opa": "ok", "x-opa-reason": "GET ok: reader"}} if {
  iss_ok
  exp_ok
  upper(method()) == "GET"
  has_realm_role("reader")
}

# POST → writer 허용
allow := {"allowed": true, "headers": {"x-opa": "ok", "x-opa-reason": "POST ok: writer"}} if {
  iss_ok
  exp_ok
  upper(method()) == "POST"
  has_realm_role("writer")
}

