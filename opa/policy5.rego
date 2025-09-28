package http.authz
import future.keywords.if

default allow := {"allowed": false, "http_status": 403, "body": "forbidden"}

############################
# payload 읽기: header 또는 metadata(jwt)
############################

get_payload() := p if {
  raw := input.attributes.request.http.headers["x-jwt-payload"]
  p := json.unmarshal(raw)
  print("DEBUG: payload from header")
} else := p if {
  md := input.attributes.metadata_context.filter_metadata["envoy.filters.http.jwt_authn"]
  v := md["jwt"]
  is_object(v)
  p := v
  print("DEBUG: payload from metadata(object)")
} else := p if {
  md := input.attributes.metadata_context.filter_metadata["envoy.filters.http.jwt_authn"]
  v := md["jwt"]
  not is_object(v)
  p := json.unmarshal(v)
  print("DEBUG: payload from metadata(string)")
}

############################
# 디버그 헬퍼
############################

debug_info(msg) if { print(sprintf("DEBUG: %v", [msg])) }

has_realm_role(role) if {
  p := get_payload()
  some i
  p.realm_access.roles[i] == role
}

valid_iss if {
  p := get_payload()
  p.iss == "http://localhost:8080/realms/demo"
}

valid_exp if {
  p := get_payload()
  time.now_ns()/1000000000 < p.exp
}

valid_claims if {
  valid_iss
  valid_exp
}

############################
# 명확한 401 (payload 없음)
############################

allow := {"allowed": false, "http_status": 401, "body": "missing jwt payload"} if {
  not input.attributes.request.http.headers["x-jwt-payload"]
  not input.attributes.metadata_context.filter_metadata["envoy.filters.http.jwt_authn"]["jwt"]
  debug_info("no jwt payload in header and metadata")
}

############################
# GET 허용 규칙 (reader) - 이유 헤더 포함
############################

allow := {
  "allowed": true,
  "headers": {"x-opa-reason": reason}
} if {
  m := input.attributes.request.http.method
  p := get_payload()

  debug_info({"method": m, "iss": p.iss, "has_reader": has_realm_role("reader"), "roles": p.realm_access.roles})

  valid_claims
  m == "GET"
  has_realm_role("reader")

  reason := "GET ok: reader"
}

############################
# POST 허용 규칙 (writer) - 이유 헤더 포함
############################

allow := {
  "allowed": true,
  "headers": {"x-opa-reason": reason}
} if {
  m := input.attributes.request.http.method
  p := get_payload()

  debug_info({"method": m, "iss": p.iss, "has_writer": has_realm_role("writer"), "roles": p.realm_access.roles})

  valid_claims
  m == "POST"
  has_realm_role("writer")

  reason := "POST ok: writer"
}

############################
# 마지막 디버그(거부 시 이유 힌트)
############################

allow := {"allowed": false, "http_status": 403, "body": "forbidden"} if {
  p := get_payload()
  m := input.attributes.request.http.method

  # 각 조건을 출력해보자
  debug_info({"deny": true,
              "method": m,
              "iss_ok": valid_iss,
              "exp_ok": valid_exp,
              "has_reader": has_realm_role("reader"),
              "has_writer": has_realm_role("writer"),
              "roles": p.realm_access.roles})
}

