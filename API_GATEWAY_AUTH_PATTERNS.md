# API Gateway Authentication & Authorization Patterns

## Do We Need to Authorize Every Request at API Gateway?

**Short Answer:** No, but it depends on your architecture and requirements.

## Key Concepts

### Authentication vs Authorization

- **Authentication** (Who you are): Verifying the user's identity via token validation
- **Authorization** (What you can do): Checking if the user has permission to perform an action

## Recommended Approach: Hybrid Strategy

### ✅ What API Gateway Should Do

1. **Token Validation (Authentication)** - For protected endpoints
   - Validate JWT token signature and expiration
   - Extract user information
   - Reject invalid/expired tokens
   - **Performance**: Fast, can be cached

2. **Basic Role Checks** - For simple authorization
   - Check if user has required role (e.g., ADMIN, USER)
   - Route-level authorization
   - **Performance**: Fast, simple checks

3. **Public Endpoint Bypass** - Skip authentication entirely
   - Public APIs (e.g., `/public/**`, `/health`, `/metrics`)
   - No token required

### ❌ What API Gateway Should NOT Do

1. **Complex Authorization Logic**
   - Resource-level permissions
   - Ownership checks (e.g., "Can user edit this specific resource?")
   - Dynamic permission evaluation
   - Business rule validation

2. **Fine-Grained Permissions**
   - Permission-based access control
   - Context-aware authorization
   - Multi-factor authorization

## Architecture Patterns

### Pattern 1: Gateway Authentication + Service Authorization (Recommended)

```
Client Request
    ↓
API Gateway
    ├─ Token Validation (Authentication) ✅
    ├─ Basic Role Check (if needed) ✅
    └─ Forward to Microservice
        ↓
Microservice
    ├─ Trust Gateway Headers ✅
    └─ Fine-Grained Authorization ✅
```

**Benefits:**
- Fast token validation at gateway
- Microservices handle complex authorization
- Better separation of concerns
- Scalable

**Example Flow:**

```java
// API Gateway validates token and adds headers
X-User-Id: 123
X-User-Email: user@example.com
X-User-Roles: USER,ADMIN

// Microservice receives request and does fine-grained check
@GetMapping("/users/{userId}/orders")
public ResponseEntity<?> getUserOrders(
    @PathVariable Long userId,
    @RequestHeader("X-User-Id") Long currentUserId,
    @RequestHeader("X-User-Roles") String roles
) {
    // Fine-grained authorization: Can user access this resource?
    if (!userId.equals(currentUserId) && !roles.contains("ADMIN")) {
        return ResponseEntity.status(403).build();
    }
    // ... business logic
}
```

### Pattern 2: Gateway Authentication Only

```
Client Request
    ↓
API Gateway
    ├─ Token Validation ✅
    └─ Forward to Microservice
        ↓
Microservice
    └─ All Authorization Logic ✅
```

**Benefits:**
- Simple gateway logic
- All authorization in one place (microservice)
- Good for services with complex authorization

### Pattern 3: Gateway Full Authorization (Not Recommended)

```
Client Request
    ↓
API Gateway
    ├─ Token Validation ✅
    ├─ Complex Authorization ❌
    └─ Forward to Microservice
        ↓
Microservice
    └─ Trust Gateway (No Authorization) ⚠️
```

**Drawbacks:**
- Gateway becomes bottleneck
- Complex logic at gateway
- Hard to maintain
- Performance issues

## Performance Considerations

### Token Validation Performance

**Option 1: Validate Every Request** (Current Implementation)
- ✅ Most secure
- ❌ Adds latency (~10-50ms per request)
- ❌ Increases load on auth service

**Option 2: Cache Token Validation Results**
- ✅ Reduces auth service load
- ✅ Faster responses
- ⚠️ Need to handle token revocation

**Option 3: Validate Token Signature Only**
- ✅ Very fast (no network call)
- ✅ Can be done at gateway
- ⚠️ Doesn't check token revocation
- ⚠️ Doesn't check user status changes

### Recommended: Hybrid Token Validation

```java
// Pseudo-code for API Gateway
public boolean validateToken(String token) {
    // 1. Quick signature validation (local, no network)
    if (!isValidSignature(token)) {
        return false;
    }
    
    // 2. Check cache for recent validation
    if (tokenCache.isValid(token)) {
        return true;
    }
    
    // 3. Call auth service for full validation (only if not cached)
    TokenValidationResponse response = authService.validateToken(token);
    
    // 4. Cache result (with TTL matching token expiration)
    tokenCache.cache(token, response, ttl);
    
    return response.isValid();
}
```

## Endpoint Classification

### Public Endpoints (No Authentication)
```
/public/**
/health
/metrics
/auth/login
/auth/register
```

### Authenticated Endpoints (Token Required, No Authorization Check)
```
/me
/profile
/dashboard
```

### Authorized Endpoints (Token + Role Check)
```
/admin/**          → Requires ADMIN role
/api/users/**     → Requires USER role
/api/admin/**     → Requires ADMIN role
```

### Resource-Specific Authorization (Token + Fine-Grained Check)
```
GET /api/users/{userId}/orders
PUT /api/users/{userId}/profile
DELETE /api/users/{userId}
```
→ Authorization done at microservice level

## Implementation Examples

### API Gateway Configuration (Kong/Spring Cloud Gateway)

```yaml
# Public endpoints - no authentication
routes:
  - path: /public/**
    plugins:
      - name: cors
  - path: /health
    plugins: []

# Authenticated endpoints - token validation only
routes:
  - path: /api/me
    plugins:
      - name: jwt-validator
        config:
          validate_token: true
          check_roles: false

# Authorized endpoints - token + role check
routes:
  - path: /api/admin/**
    plugins:
      - name: jwt-validator
        config:
          validate_token: true
          check_roles: true
          required_roles: ["ADMIN"]
```

### Microservice Authorization

```java
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    // Gateway validates token and adds headers
    @GetMapping("/{userId}/orders")
    public ResponseEntity<?> getUserOrders(
        @PathVariable Long userId,
        @RequestHeader("X-User-Id") Long currentUserId,
        @RequestHeader("X-User-Roles") List<String> roles
    ) {
        // Fine-grained authorization at service level
        if (!userId.equals(currentUserId) && !roles.contains("ADMIN")) {
            return ResponseEntity.status(403)
                .body(Map.of("error", "Access denied"));
        }
        
        // Business logic
        return ResponseEntity.ok(orderService.getOrders(userId));
    }
}
```

## Best Practices

### ✅ Do at API Gateway

1. **Token Validation** - Validate JWT signature and expiration
2. **Basic Role Checks** - Simple role-based access (ADMIN, USER)
3. **Rate Limiting** - Per user/IP rate limiting
4. **Request Logging** - Log authenticated requests
5. **Header Injection** - Add user info to headers for microservices

### ✅ Do at Microservice

1. **Resource Ownership** - Check if user owns the resource
2. **Permission Checks** - Fine-grained permissions
3. **Business Rules** - Complex authorization logic
4. **Context-Aware Auth** - Time-based, location-based, etc.
5. **Data-Level Security** - Filter results based on permissions

### ❌ Don't Do at API Gateway

1. **Database Queries** - For authorization checks
2. **Complex Business Logic** - Resource ownership, etc.
3. **Heavy Computation** - Permission evaluation
4. **Service-Specific Rules** - Keep at service level

## Caching Strategy

### Token Validation Cache

```java
// Cache token validation results
@Cacheable(value = "tokenValidation", key = "#token")
public TokenValidationResponse validateToken(String token) {
    // Call auth service
}

// Cache TTL = token expiration time
// Invalidate on logout/token revocation
```

### User Info Cache

```java
// Cache user info for faster lookups
@Cacheable(value = "userInfo", key = "#userId")
public UserInfo getUserInfo(Long userId) {
    // Fetch from database
}
```

## Security Considerations

### Token Revocation

**Problem:** Cached tokens might still be valid after revocation

**Solutions:**

1. **Short Cache TTL** - Cache for 1-5 minutes only
2. **Blacklist Check** - Check blacklist before cache
3. **Event-Driven Invalidation** - Invalidate cache on logout
4. **Token Version** - Include version in token, invalidate by version

### Token Expiration

- Always check token expiration (even if cached)
- Don't cache expired tokens
- Handle token refresh gracefully

## Recommended Configuration

### For High-Traffic Systems

```yaml
authentication:
  # Validate token signature locally (no network call)
  validate_signature: true
  
  # Cache validation results
  cache_enabled: true
  cache_ttl: 300  # 5 minutes
  
  # Full validation fallback
  full_validation_interval: 3600  # 1 hour
  
authorization:
  # Basic role checks at gateway
  gateway_role_checks: true
  
  # Fine-grained checks at service
  service_permission_checks: true
```

### For Security-Critical Systems

```yaml
authentication:
  # Always validate with auth service
  validate_signature: true
  cache_enabled: false
  
authorization:
  # All checks at gateway
  gateway_role_checks: true
  gateway_permission_checks: true
```

## Summary

| Aspect | API Gateway | Microservice |
|--------|-------------|--------------|
| **Token Validation** | ✅ Yes | ❌ No |
| **Basic Role Checks** | ✅ Yes | ✅ Yes |
| **Complex Authorization** | ❌ No | ✅ Yes |
| **Resource Ownership** | ❌ No | ✅ Yes |
| **Permission Checks** | ⚠️ Simple | ✅ Complex |
| **Public Endpoints** | ✅ Bypass | N/A |

**Recommendation:** 
- **Authenticate** (validate tokens) at API Gateway for protected endpoints
- **Authorize** (check permissions) at microservice level for fine-grained control
- Use API Gateway for simple role-based checks
- Cache token validation results for performance
- Always validate token signature locally before making network calls
