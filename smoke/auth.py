"""API checks for auth-service: internal API guard, login, tokens, refresh, lockout.

Run through smoke/run.sh, which provides AUTH_BASE, AUTH_DB, INTERNAL_TOKEN.
"""
import base64, json, os, subprocess, sys, time, urllib.request, urllib.error

BASE = os.environ["AUTH_BASE"]          # http://localhost:PORT/auth-service/api/v1
DB = os.environ["AUTH_DB"]
INTERNAL = os.environ["INTERNAL_TOKEN"]
MGMT = os.environ["AUTH_MGMT"]          # http://localhost:MGMT_PORT

ok = bad = 0
def check(name, cond, detail=""):
    global ok, bad
    if cond: ok += 1; print("  PASS", name)
    else: bad += 1; print("  FAIL", name, detail)

def call(method, path, body=None, headers=None, base=BASE):
    req = urllib.request.Request(base + path, method=method, data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items(): req.add_header(k, v)
    try:
        with urllib.request.urlopen(req) as r:
            d = r.read(); return r.status, json.loads(d) if d else None
    except urllib.error.HTTPError as e:
        d = e.read()
        try: return e.code, json.loads(d) if d else None
        except ValueError: return e.code, d.decode(errors="replace")

def sql(q): return subprocess.run(["psql", "-Atq", "-d", DB, "-c", q], check=True, capture_output=True, text=True).stdout.strip()
def claims(tok):
    p = tok.split(".")[1]; p += "=" * (-len(p) % 4); return json.loads(base64.urlsafe_b64decode(p))
def login(email, password): return call("POST", "/auth/login", {"email": email, "password": password})
INT = {"X-Internal-Token": INTERNAL}

print("== surface")
s = urllib.request.urlopen(MGMT + "/actuator/health/readiness").status; check("readiness on the management port", s == 200, s)
s, _ = call("GET", "/actuator/health"); check("actuator not on the API port", s == 404, s)
s, _ = call("POST", "/auth/register", {"email": "self@x.test", "password": "password123"}); check("self-registration disabled → 403", s == 403, s)

print("== internal API")
s, _ = call("GET", "/internal/users?email=a@x.test"); check("no internal token → 401", s == 401, s)
s, _ = call("GET", "/internal/users?email=a@x.test", headers={"X-Internal-Token": "wrong"}); check("wrong internal token → 401", s == 401, s)
s, u = call("POST", "/internal/users", {"email": "Ana@X.test", "password": "correct-horse"}, headers=INT)
check("create user → 201, email lower-cased", s == 201 and u["email"] == "ana@x.test" and u["status"] == "ACTIVE", (s, u))
s, d = call("POST", "/internal/users", {"email": "ana@x.test", "password": "another-pass"}, headers=INT); check("duplicate → 409", s == 409, (s, d))
s, d = call("POST", "/internal/users", {"email": "eve@x.test", "password": "EVE@x.test"}, headers=INT); check("email as password → 400", s == 400, (s, d))
s, d = call("POST", "/internal/users", {"email": "not-an-email", "password": "short"}, headers=INT)
check("validation → 400 with field errors", s == 400 and len(d.get("errors", [])) == 2, (s, d))
s, d = call("GET", "/internal/users?email=ANA@x.test", headers=INT); check("find by email (any case)", s == 200 and d["id"] == u["id"], (s, d))
s, _ = call("GET", "/internal/users?email=nobody@x.test", headers=INT); check("unknown email → 404", s == 404, s)
s, d = call("GET", "/internal/users?email=ana@x.test", headers=INT)
check("no password hash or lockout state in responses", "passwordHash" not in json.dumps(d) and "failed" not in json.dumps(d).lower(), d)

print("== login and tokens")
s, d = login("ANA@x.test", "correct-horse")
check("login → 200", s == 200 and d["userId"] == u["id"], (s, d))
a = claims(d["accessToken"])
check("access token is a JWT of type ACCESS; the refresh token is opaque (not a JWT)",
      a["token_type"] == "ACCESS" and d["refreshToken"].count(".") == 0 and len(d["refreshToken"]) >= 40, d["refreshToken"])
check("only the refresh token's hash is stored", sql(f"select count(*) from refresh_sessions where token_hash = '{d['refreshToken']}'") == "0"
      and sql("select count(*) from refresh_sessions") != "0")
check("expiresIn matches the access token lifetime", d["expiresIn"] == a["exp"] - a["iat"], (d["expiresIn"], a["exp"] - a["iat"]))
check("access tokens are short-lived (≤ 1 h)", a["exp"] - a["iat"] <= 3600, a)
s, n = call("POST", "/auth/refresh", {"refreshToken": d["refreshToken"]}); check("refresh → new access token", s == 200 and claims(n["accessToken"])["token_type"] == "ACCESS", (s, n))
s, _ = call("POST", "/auth/refresh", {"refreshToken": d["accessToken"]}); check("access token can't be used to refresh → 401", s == 401, s)
s, _ = call("POST", "/auth/refresh", {"refreshToken": "garbage"}); check("garbage refresh → 401", s == 401, s)
s, w = login("ana@x.test", "wrong-pass"); s2, w2 = login("nobody@x.test", "wrong-pass")
check("wrong password and unknown email look the same", s == s2 == 401 and w["detail"] == w2["detail"], (w, w2))

def avg(email, n=4):
    t = time.time()
    for _ in range(n): login(email, "wrong-pass")
    return (time.time() - t) / n
call("POST", "/internal/users", {"email": "timing@x.test", "password": "correct-horse"}, headers=INT)
known, unknown = avg("timing@x.test"), avg("ghost@x.test")
check("unknown email takes as long as a wrong password (no enumeration by timing)", 0.5 < unknown / known < 2, (round(known, 3), round(unknown, 3)))
sql("update users set failed_login_attempts = 0, locked_until = null where email = 'timing@x.test'")

print("== lockout")
call("POST", "/internal/users", {"email": "bob@x.test", "password": "correct-horse"}, headers=INT)
login("bob@x.test", "nope-1"); login("bob@x.test", "nope-2")
check("failures are counted", sql("select failed_login_attempts from users where email = 'bob@x.test'") == "2")
s, _ = login("bob@x.test", "correct-horse"); check("success resets the count", s == 200 and sql("select failed_login_attempts from users where email = 'bob@x.test'") == "0", s)
codes = [login("bob@x.test", f"nope-{i}")[0] for i in range(5)]
check("5 wrong passwords → 401 each", codes == [401] * 5, codes)
s, d = login("bob@x.test", "correct-horse")
check("then even the right password → 429 with a wait time", s == 429 and "minute" in d["detail"], (s, d))
check("lock stored in the database", sql("select locked_until > now() from users where email = 'bob@x.test'") == "t")
s, _ = login("bob@x.test", "nope-x"); check("guesses during the lock are refused without checking", s == 429, s)
sql("update users set locked_until = now() - interval '1 minute' where email = 'bob@x.test'")
s, _ = login("bob@x.test", "correct-horse"); check("after the lock expires the right password works", s == 200, s)
check("and the lock is cleared", sql("select coalesce(locked_until::text, 'null') || ':' || failed_login_attempts from users where email = 'bob@x.test'") == "null:0")

print("== inactive accounts")
s, d = login("ana@x.test", "correct-horse"); refresh = d["refreshToken"]
sql("update users set status = 'INACTIVE' where email = 'ana@x.test'")
s, _ = login("ana@x.test", "correct-horse"); check("inactive + right password → 403", s == 403, s)
s, _ = login("ana@x.test", "wrong-pass"); check("inactive + wrong password → 401 (status not revealed)", s == 401, s)
s, _ = call("POST", "/auth/refresh", {"refreshToken": refresh}); check("inactive account can't refresh → 403", s == 403, s)

print("== sessions and sign-out")
sql("update users set status = 'ACTIVE' where email = 'ana@x.test'")
s, one = login("ana@x.test", "correct-horse"); s, two = login("ana@x.test", "correct-horse")
check("a session per sign-in, with the browser recorded", sql("select count(*) from refresh_sessions s join users u on u.id = s.user_id where u.email = 'ana@x.test' and revoked_at is null and user_agent like 'Python%'") != "0")
before = sql(f"select expires_at from refresh_sessions where token_hash = encode(sha256('{one['refreshToken']}'::bytea), 'hex')")
sql(f"update refresh_sessions set expires_at = now() + interval '1 day' where token_hash = encode(sha256('{one['refreshToken']}'::bytea), 'hex')")
s, _ = call("POST", "/auth/refresh", {"refreshToken": one["refreshToken"]})
check("using a session extends it (7 days idle)", s == 200 and sql(f"select expires_at > now() + interval '6 days' from refresh_sessions where token_hash = encode(sha256('{one['refreshToken']}'::bytea), 'hex')") == "t")
s, _ = call("POST", "/auth/refresh", {"refreshToken": one["refreshToken"]}); check("refresh token isn't rotated: two tabs can both refresh", s == 200, s)
s, _ = call("POST", "/auth/logout", {"refreshToken": one["refreshToken"]}); check("sign out → 204", s == 204, s)
s, d = call("POST", "/auth/refresh", {"refreshToken": one["refreshToken"]}); check("signed-out session can't refresh → 401", s == 401, (s, d))
s, _ = call("POST", "/auth/refresh", {"refreshToken": two["refreshToken"]}); check("other sessions keep working", s == 200, s)
s, _ = call("POST", "/auth/logout", {"refreshToken": "never-existed"}); check("signing out an unknown token is quiet", s == 204, s)
sql(f"update refresh_sessions set absolute_expires_at = now() + interval '1 hour', expires_at = now() + interval '1 hour' where token_hash = encode(sha256('{two['refreshToken']}'::bytea), 'hex')")
call("POST", "/auth/refresh", {"refreshToken": two["refreshToken"]})
check("a session never outlives its 30-day cap", sql(f"select expires_at <= absolute_expires_at from refresh_sessions where token_hash = encode(sha256('{two['refreshToken']}'::bytea), 'hex')") == "t")
sql(f"update refresh_sessions set expires_at = now() - interval '1 second' where token_hash = encode(sha256('{two['refreshToken']}'::bytea), 'hex')")
s, _ = call("POST", "/auth/refresh", {"refreshToken": two["refreshToken"]}); check("expired session → 401", s == 401, s)
s, a1 = login("ana@x.test", "correct-horse"); s, a2 = login("ana@x.test", "correct-horse")
s, d = call("POST", "/auth/logout-all", headers={"Authorization": "Bearer " + a1["accessToken"]})
check("sign out everywhere", s == 200 and d["sessionsEnded"] >= 2, (s, d))
s, _ = call("POST", "/auth/refresh", {"refreshToken": a2["refreshToken"]}); check("…ends the other browser's session too", s == 401, s)
s, _ = call("POST", "/auth/logout-all", headers={"Authorization": "Bearer " + a1["refreshToken"]}); check("logout-all needs an access token", s == 401, s)
s, _ = call("POST", "/auth/logout-all"); check("…and refuses no token", s == 401, s)

print("== change password")
s, c1 = login("ana@x.test", "correct-horse"); s, c2 = login("ana@x.test", "correct-horse")
H = {"Authorization": "Bearer " + c1["accessToken"]}
s, d = call("POST", "/auth/password/change", {"currentPassword": "wrong", "newPassword": "brand-new-pass"}, headers=H)
check("wrong current password → 400, counted as a failed sign-in", s == 400 and sql("select failed_login_attempts from users where email = 'ana@x.test'") == "1", (s, d))
s, d = call("POST", "/auth/password/change", {"currentPassword": "correct-horse", "newPassword": "correct-horse"}, headers=H); check("same password → 400", s == 400, d)
s, d = call("POST", "/auth/password/change", {"currentPassword": "correct-horse", "newPassword": "ana@x.test"}, headers=H); check("email as password → 400", s == 400, d)
s, d = call("POST", "/auth/password/change", {"currentPassword": "correct-horse", "newPassword": "brand-new-pass"}, headers=H)
check("changed: a fresh session comes back", s == 200 and d["refreshToken"] and d["refreshToken"] != c1["refreshToken"], (s, d))
fresh = d
s, _ = call("POST", "/auth/refresh", {"refreshToken": c2["refreshToken"]}); check("every other session ended", s == 401, s)
s, _ = call("POST", "/auth/refresh", {"refreshToken": fresh["refreshToken"]}); check("the new session works", s == 200, s)
s, _ = login("ana@x.test", "correct-horse"); check("old password refused", s == 401, s)
s, _ = login("ana@x.test", "brand-new-pass"); check("new password works", s == 200, s)
check("password_changed_at recorded", sql("select password_changed_at is not null from users where email = 'ana@x.test'") == "t")

print("== reset password")
s, _ = call("POST", "/internal/password-resets", {"email": "ana@x.test"}); check("reset link needs the internal token", s == 401, s)
s, d = call("POST", "/internal/password-resets", {"email": "nobody@x.test"}, headers=INT); check("unknown email → 404", s == 404, s)
s, first = call("POST", "/internal/password-resets", {"email": "ANA@x.test"}, headers=INT)
check("link issued, 30 minutes, only its hash stored", s == 201 and len(first["token"]) >= 40
      and sql(f"select count(*) from password_resets where token_hash = '{first['token']}'") == "0", (s, first))
s, second = call("POST", "/internal/password-resets", {"email": "ana@x.test"}, headers=INT)
s, d = call("POST", "/auth/password/reset", {"token": first["token"], "newPassword": "reset-pass-1"}); check("an older link stops working when a new one is issued", s == 400, (s, d))
s, live = login("ana@x.test", "brand-new-pass")
for _ in range(5): login("ana@x.test", "wrong")
s, _ = login("ana@x.test", "brand-new-pass"); check("(account locked by guesses)", s == 429, s)
s, d = call("POST", "/auth/password/reset", {"token": second["token"], "newPassword": "short"}); check("too short → 400", s == 400, d)
s, d = call("POST", "/auth/password/reset", {"token": second["token"], "newPassword": "reset-pass-1"}); check("reset → 204", s == 204, (s, d))
s, _ = login("ana@x.test", "reset-pass-1"); check("new password works, and the lock is cleared", s == 200, s)
s, _ = call("POST", "/auth/refresh", {"refreshToken": live["refreshToken"]}); check("sessions from before the reset ended", s == 401, s)
s, d = call("POST", "/auth/password/reset", {"token": second["token"], "newPassword": "reset-pass-2"}); check("a link works once", s == 400, d)
s, third = call("POST", "/internal/password-resets", {"email": "ana@x.test"}, headers=INT)
sql(f"update password_resets set expires_at = now() - interval '1 second' where used_at is null")
s, d = call("POST", "/auth/password/reset", {"token": third["token"], "newPassword": "reset-pass-3"}); check("expired link → 400", s == 400, d)
sql("update users set status = 'INACTIVE' where email = 'bob@x.test'")
s, _ = call("POST", "/internal/password-resets", {"email": "bob@x.test"}, headers=INT); check("no link for an inactive account", s == 404, s)

print("== sign in with a provider (mock OpenID Connect)")
import http.cookies, urllib.parse
OIDC = os.environ["OIDC_BASE"]
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None
opener = urllib.request.build_opener(NoRedirect)
def raw(url, method="GET", body=None, headers=None):
    req = urllib.request.Request(url, method=method, data=body)
    for k, v in (headers or {}).items(): req.add_header(k, v)
    try:
        r = opener.open(req); return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
def as_user(**user):
    raw(OIDC + "/next-user", "POST", json.dumps(user).encode(), {"Content-Type": "application/json"})
def sso(next_path=None, tamper_cookie=False, cancel=False):
    """Runs the browser side: start → provider → callback. Returns the final Location."""
    s, h, _ = raw(BASE + "/auth/sso/oidc/start" + (f"?next={urllib.parse.quote(next_path)}" if next_path else ""))
    if s != 302: return f"start answered {s}"
    cookie = http.cookies.SimpleCookie(h.get("Set-Cookie")); state_cookie = cookie["credintel_sso_state"].value
    s, h, _ = raw(h["Location"])                      # the provider signs the test user in, sends back
    callback = h["Location"]
    if cancel: callback = callback.split("?")[0] + "?error=access_denied&state=x"
    s, h, _ = raw(callback, headers={"Cookie": "credintel_sso_state=" + ("forged" if tamper_cookie else state_cookie)})
    return h.get("Location", f"callback answered {s}")
def code_of(location):
    frag = urllib.parse.parse_qs(location.split("#", 1)[1]) if "#" in location else {}
    return frag.get("code", [None])[0], frag.get("next", [None])[0]

s, d = call("GET", "/auth/sso/providers"); check("providers list shows the configured one", d == [{"id": "oidc", "name": "Test SSO"}], d)
s, h, _ = raw(BASE + "/auth/sso/oidc/start?next=/invite/abc")
loc = urllib.parse.urlparse(h.get("Location", "")); q = dict(urllib.parse.parse_qsl(loc.query))
check("start: to the provider with state, nonce, PKCE S256, our callback", s == 302 and q.get("code_challenge_method") == "S256"
      and q.get("state") and q.get("nonce") and q.get("redirect_uri", "").endswith("/auth-service/api/v1/auth/sso/oidc/callback"), q)
check("state cookie: HttpOnly, SameSite=Lax, scoped to the SSO path", "HttpOnly" in h.get("Set-Cookie", "") and "SameSite=Lax" in h.get("Set-Cookie", "")
      and "Path=/auth-service/api/v1/auth/sso" in h.get("Set-Cookie", ""), h.get("Set-Cookie"))
check("only the state's hash is stored", sql(f"select count(*) from sso_states where state_hash = '{q.get('state')}'") == "0")

as_user(sub="g-100", email="New.Person@Example.test", email_verified=True)
loc = sso("/invite/abc")
code, nxt = code_of(loc)
check("callback → the app's completion page with a one-time code in the #fragment, and the next path", "/sso/complete#code=" in loc and nxt == "/invite/abc", loc)
s, d = call("POST", "/auth/sso/exchange", {"code": code})
check("exchange → a normal session", s == 200 and d["email"] == "new.person@example.test" and d["refreshToken"], (s, d))
new_user = d["userId"]
s, _ = call("POST", "/auth/sso/exchange", {"code": code}); check("the code works once", s == 401, s)
check("a new account, no password, linked to the provider account",
      sql(f"select (password_hash is null)::text || ':' || (select count(*) from user_identities where user_id = u.id) from users u where id = '{new_user}'") == "true:1")
s, _ = login("new.person@example.test", "any-password-at-all"); check("no password sign-in for it", s == 401, s)

as_user(sub="g-100", email="changed@example.test", email_verified=True)
code, _ = code_of(sso()); s, d = call("POST", "/auth/sso/exchange", {"code": code})
check("same provider account → same user, even if its email changed there", s == 200 and d["userId"] == new_user, d)

call("POST", "/internal/users", {"email": "existing@x.test", "password": "correct-horse"}, headers=INT)
as_user(sub="g-200", email="EXISTING@x.test", email_verified=True)
code, _ = code_of(sso()); s, d = call("POST", "/auth/sso/exchange", {"code": code})
check("verified email of an existing account → linked to it", s == 200 and d["email"] == "existing@x.test", d)
s, _ = login("existing@x.test", "correct-horse"); check("its password still works too", s == 200, s)

as_user(sub="g-300", email="victim@x.test", email_verified=False)
loc = sso(); check("unverified email → refused, sign-in page says why", loc.endswith("/login?sso_error=unverified_email"), loc)
as_user(sub="g-301", email_verified=True)
loc = sso(); check("no email → refused", loc.endswith("/login?sso_error=no_email"), loc)
as_user(sub="g-302", email="x@x.test", email_verified=True)
loc = sso(tamper_cookie=True); check("state cookie doesn't match (login CSRF) → refused", loc.endswith("/login?sso_error=expired"), loc)
loc = sso(cancel=True); check("cancelled at the provider → back to sign-in", loc.endswith("/login?sso_error=cancelled"), loc)
as_user(sub="g-303", email="y@x.test", email_verified=True, nonce="not-the-nonce")
loc = sso(); check("wrong nonce → refused", loc.endswith("/login?sso_error=bad_token"), loc)
as_user(sub="g-304", email="y@x.test", email_verified=True, aud="someone-else")
loc = sso(); check("token for another app (audience) → refused", loc.endswith("/login?sso_error=bad_token"), loc)
as_user(sub="g-305", email="y@x.test", email_verified=True, iss="https://evil.example")
loc = sso(); check("wrong issuer → refused", loc.endswith("/login?sso_error=bad_token"), loc)
as_user(sub="g-306", email="z@x.test", email_verified=True)
_, nxt = code_of(sso("//evil.example/steal")); check("an outside next address is dropped", nxt is None, nxt)
sql("update users set status = 'INACTIVE' where email = 'existing@x.test'")
as_user(sub="g-200", email="existing@x.test", email_verified=True)
loc = sso(); check("inactive account → refused", loc.endswith("/login?sso_error=inactive"), loc)
s, h, _ = raw(BASE + "/auth/sso/google/start"); check("a provider that isn't set up → sign-in page", s == 302 and "sso_error=unknown_provider" in h.get("Location", ""), h.get("Location"))
s, link = call("POST", "/internal/password-resets", {"email": "new.person@example.test"}, headers=INT)
s, _ = call("POST", "/auth/password/reset", {"token": link["token"], "newPassword": "now-with-a-password"})
s, _ = login("new.person@example.test", "now-with-a-password"); check("a provider-only account can add a password with a reset link", s == 200, s)

print(f"{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
