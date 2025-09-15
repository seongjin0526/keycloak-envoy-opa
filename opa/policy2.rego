package http.authz
import future.keywords.if

# 기본 거부
default allow := {"allowed": false, "http_status": 403, "body": "forbidden"}

############################
# 헬퍼 (값을 반환하는 함수 규칙)
############################

# JWT 페이로드 객체를 반환
get_payload() := p if {
  raw := input.attributes.request.http.headers["x-jwt-payload"]
  p := json.unmarshal(raw)
}

# 클레임 검증 (iss/exp)
valid_claims if {
  p := get_payload()
  p.iss == "http://localhost:8080/realms/demo"   # 현재 토큰 iss와 일치
  time.now_ns()/1000000000 < p.exp
}

# Realm 역할 보유 여부
has_realm_role(role) if {
  p := get_payload()
  roles := p.realm_access.roles
  roles[_] == role
}

############################
# 인가 규칙
############################

# JWT 페이로드 헤더 없으면 401
allow := {"allowed": false, "http_status": 401, "body": "missing jwt payload"} if {
  not input.attributes.request.http.headers["x-jwt-payload"]
}

# GET → reader 필요
allow := {"allowed": true, "headers": {"x-opa": "ok"}} if {
  valid_claims
  input.attributes.request.http.method == "GET"
  has_realm_role("reader")
}

# POST → writer 필요
allow := {"allowed": true, "headers": {"x-opa": "ok"}} if {
  valid_claims
  input.attributes.request.http.method == "POST"
  has_realm_role("writer")
}

