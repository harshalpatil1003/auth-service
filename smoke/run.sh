#!/usr/bin/env bash
# API smoke checks for auth-service: boots the jar against a throwaway Postgres database with a
# throwaway key pair and runs smoke/auth.py. Exit code 0 = all passed.
#
#   smoke/run.sh                 build, then check
#   SKIP_BUILD=1 smoke/run.sh    reuse target/*.jar
#
# Needs Java 17, python3, psql/createdb/dropdb, openssl, curl; Postgres via PG* variables.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PORT=${SMOKE_PORT:-8283}
MGMT_PORT=${SMOKE_MGMT_PORT:-8284}
export AUTH_DB=${SMOKE_DB:-auth_smoke}
export INTERNAL_TOKEN=$(openssl rand -hex 32)
WORK=$(mktemp -d)
APP_PID=""
OIDC_PID=""
OIDC_PORT=${SMOKE_OIDC_PORT:-8295}

cleanup() {
  [[ -n $APP_PID ]] && kill "$APP_PID" 2>/dev/null && wait "$APP_PID" 2>/dev/null
  [[ -n $OIDC_PID ]] && kill "$OIDC_PID" 2>/dev/null
  [[ -z ${KEEP_DB:-} ]] && dropdb --if-exists "$AUTH_DB" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

if [[ -z ${SKIP_BUILD:-} ]]; then
  echo "== build"; ./mvnw -q clean package -DskipTests || exit 1
fi
JAR=$(ls target/auth-service-*.jar | head -1)

dropdb --if-exists "$AUTH_DB" && createdb "$AUTH_DB" || exit 1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK/jwt_private.pem" 2>/dev/null
openssl pkey -in "$WORK/jwt_private.pem" -pubout -out "$WORK/jwt_public.pem"

DB_ARGS=(--spring.datasource.url="jdbc:postgresql://${PGHOST:-localhost}:${PGPORT:-5432}/$AUTH_DB")
[[ -n ${PGUSER:-} ]] && DB_ARGS+=(--spring.datasource.username="$PGUSER")
[[ -n ${PGPASSWORD:-} ]] && DB_ARGS+=(--spring.datasource.password="$PGPASSWORD")

# a mock OpenID Connect provider for the sign-in-with-provider checks
python3 smoke/mock_oidc.py "$OIDC_PORT" test-client test-secret &
OIDC_PID=$!
for _ in $(seq 1 20); do curl -sf "http://127.0.0.1:$OIDC_PORT/jwks" > /dev/null && break; sleep 0.5; done

echo "== start auth-service (log: target/smoke-auth.log)"
java -jar "$JAR" --server.port="$PORT" --management.server.port="$MGMT_PORT" "${DB_ARGS[@]}" \
  --credintel.jwt.private-key="file:$WORK/jwt_private.pem" --credintel.jwt.public-key="file:$WORK/jwt_public.pem" \
  --credintel.internal.token="$INTERNAL_TOKEN" --eureka.client.enabled=false \
  --credintel.sso.oidc.issuer="http://127.0.0.1:$OIDC_PORT" --credintel.sso.oidc.name="Test SSO" \
  --credintel.sso.oidc.client-id=test-client --credintel.sso.oidc.client-secret=test-secret \
  --credintel.sso.public-url="http://localhost:$PORT" \
  > target/smoke-auth.log 2>&1 &
APP_PID=$!
for _ in $(seq 1 60); do
  curl -sf "http://localhost:$MGMT_PORT/actuator/health/readiness" > /dev/null && break
  kill -0 "$APP_PID" 2>/dev/null || { echo "auth-service exited during startup:"; tail -40 target/smoke-auth.log; exit 1; }
  sleep 1
done

export AUTH_BASE="http://localhost:$PORT/auth-service/api/v1" AUTH_MGMT="http://localhost:$MGMT_PORT" OIDC_BASE="http://127.0.0.1:$OIDC_PORT"
python3 smoke/auth.py
