package http.authz
import future.keywords.if

default allow := {"allowed": false, "http_status": 403, "body": "forbidden"}

# JWT payload 가져오기: 1) header x-jwt-payload(JSON string), 2) metadata(jwt)
get_payload() := p if {
  raw := input.attributes.request.http.headers["x-jwt-payload"]
  p := json.unmarshal(raw)
  print("payload from header")
} else := p if {
  md := input.attributes.metadata_context.filter_metadata["envoy.filters.http.jwt_authn"]
  v := md["jwt"]
  is_object(v)
  p := v
  print("payload from metadata (object)")
} else := p if {
  md := input.attributes.metadata_context.filter_metadata["envoy.filters.http.jwt_authn"]
  v := md["jwt"]
  not is_object(v)
  p := json.unmarshal(v)
  print("payload from metadata (string)")
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

# payload가 전혀 없으면 401로 명확히 표출
allow := {"allowed": false, "http_status": 401, "body": "missing jwt payload"} if {
  not input.attributes.request.http.headers["x-jwt-payload"]
  not input.attributes.metadata_context.filter_metadata["envoy.filters.http.jwt_authn"]["jwt"]
  print("no jwt payload in header nor metadata")
}

# GET → reader 허용
allow := {"allowed": true, "headers": {"x-opa": "ok"}} if {
  valid_claims
  input.attributes.request.http.method == "GET"
  has_realm_role("reader")
  print("GET allowed for reader")
}

# POST → writer 허용 (writer-user 테스트용)
allow := {"allowed": true, "headers": {"x-opa": "ok"}} if {
  valid_claims
  input.attributes.request.http.method == "POST"
  has_realm_role("writer")
  print("POST allowed for writer")
}

