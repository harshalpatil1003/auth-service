# API Gateway Integration Guide

This document describes how to use the Authentication and Authorization Service with an API Gateway for multiple microservices.

## Overview

The auth service provides JWT-based authentication and authorization endpoints that can be used by an API Gateway to:
- Validate tokens from client requests
- Check user roles and permissions
- Get user information
- Support service-to-service authentication

## Architecture

```
Client → API Gateway → Auth Service (Token Validation/Authorization)
              ↓
       Microservices (with token validation)
```

## Endpoints for API Gateway

### 1. Token Validation
**POST** `/auth/validate`

Validates a JWT token and returns user information.

**Request:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (Valid Token):**
```json
{
  "valid": true,
  "subject": "user@example.com",
  "userId": 1,
  "email": "user@example.com",
  "roles": ["USER", "ADMIN"],
  "enabled": true,
  "message": "Token is valid"
}
```

**Response (Invalid Token):**
```json
{
  "valid": false,
  "message": "Invalid or expired token"
}
```

### 2. Token Introspection (OAuth2 Compatible)
**POST** `/auth/introspect?token={token}`

Returns detailed token information in OAuth2 introspection format.

**Response:**
```json
{
  "active": true,
  "sub": "user@example.com",
  "userId": 1,
  "email": "user@example.com",
  "roles": ["USER", "ADMIN"],
  "enabled": true,
  "type": "ACCESS",
  "iss": "auth-service",
  "iat": 1234567890,
  "exp": 1234654290
}
```

### 3. User Info
**POST** `/auth/userinfo?token={token}`

Returns user information from token.

**Response:**
```json
{
  "userId": 1,
  "email": "user@example.com",
  "username": "user@example.com",
  "roles": ["USER", "ADMIN"],
  "enabled": true
}
```

### 4. Authorization Check
**POST** `/auth/authorize`

Checks if user has required roles/permissions.

**Request:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "requiredRoles": ["ADMIN"],
  "requiredPermissions": [],
  "resource": "/api/admin/users",
  "action": "GET"
}
```

**Response (Authorized):**
```json
{
  "authorized": true,
  "message": "User is authorized"
}
```

**Response (Not Authorized):**
```json
{
  "authorized": false,
  "message": "User does not have required roles",
  "reason": "INSUFFICIENT_ROLES"
}
```

### 5. Quick Role Check
**POST** `/auth/check-role?token={token}&role={role}`

Quick check if user has a specific role.

**Response:**
```json
true  // or false
```

### 6. Service-to-Service Authentication
**POST** `/auth/service/validate?serviceToken={token}`

Validates service tokens for inter-service communication.

**Response:**
```json
{
  "valid": true,
  "serviceId": "service-name",
  "roles": ["SERVICE"]
}
```

## API Gateway Integration Examples

### Kong API Gateway

```lua
-- Kong plugin for token validation
local http = require "resty.http"
local httpc = http.new()

local token = ngx.req.get_headers()["Authorization"]
if not token then
  ngx.status = 401
  ngx.say('{"error": "Missing token"}')
  return ngx.exit(401)
end

token = string.gsub(token, "Bearer ", "")

local res, err = httpc:request_uri("http://auth-service:8080/auth/validate", {
  method = "POST",
  body = '{"token":"' .. token .. '"}',
  headers = {
    ["Content-Type"] = "application/json"
  }
})

if res.status ~= 200 then
  ngx.status = 401
  return ngx.exit(401)
end

local json = require "cjson"
local data = json.decode(res.body)

if not data.valid then
  ngx.status = 401
  ngx.say('{"error": "Invalid token"}')
  return ngx.exit(401)
end

-- Add user info to headers for downstream services
ngx.req.set_header("X-User-Id", data.userId)
ngx.req.set_header("X-User-Email", data.email)
ngx.req.set_header("X-User-Roles", table.concat(data.roles, ","))
```

### Spring Cloud Gateway

```java
@Component
public class TokenValidationGatewayFilter implements GatewayFilter {
    
    @Autowired
    private WebClient.Builder webClientBuilder;
    
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String token = extractToken(request);
        
        if (token == null) {
            return unauthorized(exchange);
        }
        
        return webClientBuilder.build()
            .post()
            .uri("http://auth-service/auth/validate")
            .bodyValue(Map.of("token", token))
            .retrieve()
            .bodyToMono(TokenValidationResponse.class)
            .flatMap(response -> {
                if (!response.isValid()) {
                    return unauthorized(exchange);
                }
                
                // Add user info to headers
                ServerHttpRequest modifiedRequest = request.mutate()
                    .header("X-User-Id", String.valueOf(response.getUserId()))
                    .header("X-User-Email", response.getEmail())
                    .header("X-User-Roles", String.join(",", response.getRoles()))
                    .build();
                
                return chain.filter(exchange.mutate().request(modifiedRequest).build());
            })
            .onErrorResume(e -> unauthorized(exchange));
    }
    
    private String extractToken(ServerHttpRequest request) {
        String authHeader = request.getHeaders().getFirst("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }
    
    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.setComplete();
    }
}
```

### NGINX with Lua

```nginx
location /api/ {
    access_by_lua_block {
        local http = require "resty.http"
        local httpc = http.new()
        local json = require "cjson"
        
        local token = ngx.req.get_headers()["Authorization"]
        if not token then
            ngx.status = 401
            ngx.say('{"error": "Missing token"}')
            ngx.exit(401)
        end
        
        token = string.gsub(token, "Bearer ", "")
        
        local res, err = httpc:request_uri("http://auth-service:8080/auth/validate", {
            method = "POST",
            body = json.encode({token = token}),
            headers = {
                ["Content-Type"] = "application/json"
            }
        })
        
        if res.status ~= 200 then
            ngx.status = 401
            ngx.exit(401)
        end
        
        local data = json.decode(res.body)
        if not data.valid then
            ngx.status = 401
            ngx.say('{"error": "Invalid token"}')
            ngx.exit(401)
        end
        
        -- Pass user info to upstream
        ngx.req.set_header("X-User-Id", data.userId)
        ngx.req.set_header("X-User-Email", data.email)
        ngx.req.set_header("X-User-Roles", table.concat(data.roles, ","))
    }
    
    proxy_pass http://backend-service;
}
```

## JWT Token Structure

JWT tokens contain the following claims:

```json
{
  "sub": "user@example.com",
  "userId": 1,
  "email": "user@example.com",
  "roles": ["USER", "ADMIN"],
  "enabled": true,
  "type": "ACCESS",
  "iss": "auth-service",
  "iat": 1234567890,
  "exp": 1234654290
}
```

## Security Considerations

1. **Token Validation**: Always validate tokens at the API Gateway level before forwarding requests to microservices
2. **HTTPS**: Use HTTPS for all communication between API Gateway and auth service
3. **Token Expiration**: Tokens have expiration times - handle refresh token flow
4. **Rate Limiting**: Implement rate limiting on auth endpoints to prevent abuse
5. **Token Blacklisting**: Consider implementing token blacklisting for logout functionality
6. **Service Tokens**: Use separate service tokens for inter-service communication

## Configuration

Add these properties to `application.properties`:

```properties
# JWT Configuration
jwt.secret=your-secret-key-minimum-256-bits
jwt.access-token-expiration=86400000  # 24 hours in milliseconds
jwt.refresh-token-expiration=604800000  # 7 days in milliseconds
jwt.issuer=auth-service
```

## Microservice Integration

Microservices can validate tokens independently or rely on API Gateway:

1. **API Gateway Validation** (Recommended): API Gateway validates all tokens, microservices trust API Gateway headers
2. **Independent Validation**: Each microservice validates tokens using the auth service

### Option 1: Trust API Gateway Headers

Microservices can trust headers set by API Gateway:

```java
@RestController
public class MyController {
    
    @GetMapping("/resource")
    public ResponseEntity<?> getResource(@RequestHeader("X-User-Id") Long userId,
                                        @RequestHeader("X-User-Email") String email) {
        // Use user info from headers (trusted from API Gateway)
        return ResponseEntity.ok("Resource for user: " + userId);
    }
}
```

### Option 2: Independent Token Validation

Each microservice validates tokens directly:

```java
@Service
public class TokenValidationService {
    
    @Autowired
    private RestTemplate restTemplate;
    
    public TokenValidationResponse validateToken(String token) {
        TokenValidationRequest request = new TokenValidationRequest(token);
        return restTemplate.postForObject(
            "http://auth-service/auth/validate",
            request,
            TokenValidationResponse.class
        );
    }
}
```

## Error Handling

The auth service returns appropriate HTTP status codes:
- `200 OK`: Request successful
- `401 UNAUTHORIZED`: Invalid or expired token
- `400 BAD REQUEST`: Malformed request
- `500 INTERNAL SERVER ERROR`: Server error

## Testing

### Test Token Validation

```bash
curl -X POST http://localhost:8080/auth/validate \
  -H "Content-Type: application/json" \
  -d '{"token":"your-jwt-token"}'
```

### Test Authorization

```bash
curl -X POST http://localhost:8080/auth/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "token": "your-jwt-token",
    "requiredRoles": ["ADMIN"]
  }'
```

### Test User Info

```bash
curl -X POST "http://localhost:8080/auth/userinfo?token=your-jwt-token"
```

## Performance Considerations

1. **Caching**: Consider caching token validation results at API Gateway level
2. **Connection Pooling**: Use connection pooling for HTTP calls to auth service
3. **Timeouts**: Configure appropriate timeouts for auth service calls
4. **Circuit Breaker**: Implement circuit breaker pattern for auth service calls
