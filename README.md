# keycloak-envoy-opa
Keycloak 계정 역할 관리를 envoy proxy - opa를 연동하여 rego로 관리해보는 샘플 구성

# Keycloak에서 설정할것

Clients → my-api → Client scopes → Assigned default client scopes → Add client scope 클릭 → roles 선택 → Add

# keycloak 설정 후 아래 처럼 그대로 따라하면 됨
```bash
$ sudo docker compose up
```

```bash
$ TOKEN=$(curl -s -X POST "http://localhost:8080/realms/demo/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=my-api" \
  -d "grant_type=password" \
  -d "username=writer-user" \
  -d "password=writer123" \
  | jq -r .access_token)
```
```bash
$ curl -v http://localhost:8081/ -H "Authorization: Bearer $TOKEN"
```
