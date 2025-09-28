package http.authz
import future.keywords.if

default allow := {"allowed": false, "http_status": 403, "body": "forbidden"}

# JWT payload 가져오기: 1) 헤더 x-jwt-payload (JSON string) 2) 메타데이터(jwt)
get_payload() := p if {
  # 1) header 경로
  raw := input.attributes.request.http.headers["x-jwt-payload"]
  p := json.unmarshal(raw)
} else := p if {
  # 2) metadata 경로 (envoy.filters.http.jwt_authn / key "jwt")
  md := input.attributes.metadata_context.filter_metadata["envoy.filters.http.jwt_authn"]
  v := md["jwt"]
  # v가 이미 객체(map)일 수도 있고 문자열일 수도 있음 → 문자열이면 파싱
  is_object(v)
  p := v
} else := p if {
  md := input.attributes.metadata_context.filter_metadata["envoy.filters.http.jwt_authn"]
  v := md["jwt"]
  not is_object(v)
  p := json.unmarshal(v)
}

valid_claims if {
  p := get_payload()
  p.iss == "http://localhost:8080/realms/demo"
  time.now_ns()/1000000000 < p.exp
}

has_realm_role(role) if {
  p := get_payload()
  p.realm_access.roles[_] == role
}

allow := {"allowed": false, "http_status": 401, "body": "missing jwt payload"} if {
  not input.attributes.request.http.headers["x-jwt-payload"]
  not input.attributes.metadata_context.filter_metadata["envoy.filters.http.jwt_authn"]["jwt"]
}

allow := {"allowed": true, "headers": {"x-opa": "ok"}} if {
  valid_claims
  input.attributes.request.http.method == "GET"
  has_realm_role("reader")
}

allow := {"allowed": true, "headers": {"x-opa": "ok"}} if {
  valid_claims
  input.attributes.request.http.method == "POST"
  has_realm_role("writer")
}

