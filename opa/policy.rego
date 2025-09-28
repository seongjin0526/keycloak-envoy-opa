package http.authz

default allow := false

allow if {
  headers := input.attributes.request.http.headers

  # Authorization: Bearer <JWT>
  auth := headers.authorization
  parts := split(auth, " ")
  count(parts) == 2

  token := parts[1]

  # io.jwt.decode(token) => [header, payload, signature]
  [header, _, _] := io.jwt.decode(token)

  # alg 가 RS256 인 경우만 허용
  header.alg == "RS256"
}

