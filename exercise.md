# Leen IDP Model Extension Exercise
## Identity Provider (IDP) Model Mapping for Okta and MS Entra ID

**Candidate Solution**  
**Date:** October 23, 2025

---

## Executive Summary

This document outlines the approach and mappings for extending Leen's normalized IDP model to support Okta and Microsoft Entra ID (formerly Azure AD). The goal is to enhance the `user` object with security-relevant attributes and design a new `policy` object for organizational access policies. This work enables security investigations, access reviews, and compliance workflows across multiple identity providers.

---

## Approach

### 1. Research Phase
- **Reviewed Leen's existing model philosophy**: Examined Leen's documentation and changelog to understand their normalization approach for VMS, EDR, and other security categories
- **Analyzed API documentation**: Deep-dived into Okta Users API, User Factors API, Policy API, and Microsoft Graph API (Users, Authentication Methods, Conditional Access)
- **Identified key endpoints**: Mapped relevant endpoints that provide user attributes, MFA status, and policy information
- **Gap analysis**: Documented where data cannot be directly mapped or requires inference

### 2. Design Principles
- **Consistency with Leen's existing models**: Follow similar naming conventions and field structures
- **Security-first approach**: Prioritize fields that support security investigations and access reviews
- **Practical normalization**: Balance between comprehensive coverage and maintainability
- **Clear provenance**: Document which source fields map to normalized fields

### 3. Key Considerations
- **MFA enrollment varies significantly** between providers in how it's exposed via API
- **Policy models differ fundamentally**: Okta uses policy-rule hierarchies; Entra uses conditional access with complex condition sets
- **User types and roles** have different taxonomies across providers
- **Rate limiting** differs significantly (Okta: per-endpoint limits; Entra: token-bucket throttling)

---

## User Object Enhancement

### Relevant API Endpoints

#### Okta
- **Primary Endpoint**: `GET /api/v1/users/{id}`
  - Returns user profile, status, credentials, type information
  - **Permissions Required**: `okta.users.read`
  - **Rate Limit**: 1000 requests/minute per org

- **MFA Enrollment**: `GET /api/v1/users/{id}/factors`
  - Lists all enrolled MFA factors for a user
  - **Permissions Required**: `okta.users.read`
  - **Rate Limit**: 1000 requests/minute per org
  - **Note**: Only returns factors for users in highest priority authenticator enrollment policy

- **User Type Details**: `GET /api/v1/meta/types/user/{typeId}`
  - Retrieves user type schema (referenced from user object)
  - **Permissions Required**: `okta.schemas.read`

#### Microsoft Entra ID
- **Primary Endpoint**: `GET /v1.0/users/{id}`
  - Returns basic user profile (limited attributes by default)
  - **Permissions Required**: `User.Read.All` (Delegated) or `User.Read.All` (Application)
  - **Rate Limit**: 2000 requests/10 minutes per app per tenant
  - **Must use `$select`** to retrieve extended properties

- **MFA Registration Details**: `GET /beta/reports/credentialUserRegistrationDetails`
  - **CRITICAL**: Only available in beta endpoint, not v1.0
  - Returns MFA registration status and methods per user
  - **Permissions Required**: `Reports.Read.All` (Application), `UserAuthenticationMethod.Read.All`
  - **Rate Limit**: Part of general Graph API limits
  - **Need clarification**: Whether v1.0 equivalent will be available

- **Authentication Methods** (Alternative): `GET /v1.0/users/{id}/authentication/methods`
  - Lists registered authentication methods for specific user
  - **Permissions Required**: `UserAuthenticationMethod.Read.All`
  - **Note**: More granular than reports endpoint but requires per-user calls

---

### User Field Mappings

| Leen Normalized Field | Type | Okta Source | MS Entra ID Source | Notes |
|----------------------|------|-------------|-------------------|-------|
| **id** | string | `id` | `id` | Native UUID from provider |
| **user_principal_name** | string | `profile.login` | `userPrincipalName` | Primary login identifier |
| **email** | string | `profile.email` | `mail` or `userPrincipalName` | Entra: `mail` can be null; fallback to UPN |
| **display_name** | string | `profile.firstName + " " + profile.lastName` | `displayName` | Constructed from name parts in Okta |
| **first_name** | string | `profile.firstName` | `givenName` | - |
| **last_name** | string | `profile.lastName` | `surname` | - |
| **status** | string | `status` | `accountEnabled` | **Requires normalization** (see Status Mapping) |
| **user_type** | string | `type.id` (lookup via Type API) | `userType` | Entra: often null; common values: "Member", "Guest" |
| **job_title** | string | `profile.title` | `jobTitle` | - |
| **department** | string | `profile.department` | `department` | - |
| **employee_id** | string | `profile.employeeNumber` | `employeeId` | - |
| **manager_id** | string | N/A | `manager.id` via `/users/{id}/manager` | **Gap in Okta**: Not directly available in user object |
| **is_admin** | boolean | Derived from assigned admin roles | Derived from `memberOf` (admin groups) or directory roles | **Requires inference** (see Admin Detection) |
| **created_at** | datetime | `created` | `createdDateTime` | ISO 8601 format |
| **last_sign_in** | datetime | `lastLogin` | Via `/beta/users/{id}/signInActivity` | **Entra limitation**: signInActivity in beta only; requires Premium P1+ |
| **mfa_enrolled** | boolean | Derived from factors list | Derived from registration details | **See MFA Enrollment Mapping** |
| **mfa_methods** | array[string] | List of `factorType` from factors endpoint | List of method types from auth methods | **See MFA Methods Mapping** |
| **mfa_status** | string | Aggregate of factor statuses | From `isMfaRegistered` + method states | **See MFA Status Mapping** |
| **last_password_change** | datetime | `passwordChanged` | `lastPasswordChangeDateTime` | Entra: Requires $select |
| **account_locked** | boolean | `status === "LOCKED_OUT"` or check via `/users/{id}/blocks` | Check sign-in activity or Entra ID Protection | **Need clarification**: Best source in Entra |

---

### Status Value Normalization

Different status models need to be mapped to common values:

| Leen Normalized Status | Okta Status | Entra ID Equivalent |
|-----------------------|-------------|---------------------|
| `active` | `ACTIVE` | `accountEnabled: true` + not deleted |
| `provisioned` | `PROVISIONED` | Account exists but may not be fully set up |
| `staged` | `STAGED` | Account created but not activated |
| `suspended` | `SUSPENDED` | Blocked from sign-in (via Conditional Access or admin action) |
| `deprovisioned` | `DEPROVISIONED` | `accountEnabled: false` or soft deleted |
| `deleted` | Not returned by API (hard deleted) | In `/directory/deletedItems` |
| `locked` | `LOCKED_OUT` | Check via sign-in blocks or risk detections |
| `password_expired` | `PASSWORD_EXPIRED` | Check password policies + lastPasswordChange |
| `recovery` | `RECOVERY` | In password reset flow |

**Need clarification**: Best practice for mapping Entra's varied blocking mechanisms (Conditional Access blocks, admin blocks, risk-based blocks) to a single status field.

---

### MFA Enrollment Status Mapping

#### Okta MFA Detection
- **Endpoint**: `GET /api/v1/users/{id}/factors`
- **Logic**: 
  ```
  mfa_enrolled = factors.length > 0 AND any(factors, f => f.status == "ACTIVE")
  mfa_methods = factors.filter(f => f.status == "ACTIVE").map(f => normalize_factor_type(f.factorType))
  mfa_status = determine_from_factor_states(factors)
  ```

#### Entra ID MFA Detection (Preferred Method)
- **Endpoint**: `GET /beta/reports/credentialUserRegistrationDetails`
- **Logic**:
  ```
  mfa_enrolled = isMfaRegistered == true
  mfa_methods = methodsRegistered (array of method names)
  mfa_status = "registered" if isMfaRegistered else "not_registered"
  ```
- **Limitation**: Beta endpoint only; need v1.0 alternative or accept beta dependency

#### Entra ID MFA Detection (Alternative Method)
- **Endpoint**: `GET /v1.0/users/{id}/authentication/methods`
- **Logic**: Check for presence of MFA-capable methods (excluding password)
- **Trade-off**: Requires per-user API call vs. bulk report; but uses stable v1.0 endpoint

#### Normalized MFA Status Values
| Status | Description |
|--------|-------------|
| `registered` | User has active MFA method(s) enrolled |
| `pending_activation` | User enrolled but hasn't activated (Okta only) |
| `not_registered` | No MFA methods enrolled |
| `not_setup` | Org-level MFA available but user hasn't enrolled |
| `unavailable` | Cannot determine (permissions issue or provider limitation) |

---

### MFA Methods Normalization

| Leen Normalized Method | Okta factorType | Entra ID Method Type |
|-----------------------|-----------------|----------------------|
| `sms` | `sms` | `sms` via phoneMethods |
| `voice_call` | `call` | `voice` via phoneMethods |
| `totp` | `token:software:totp` | `softwareOath` |
| `hardware_token` | `token:hardware` | N/A (not directly supported) |
| `push_notification` | `push` | `microsoftAuthenticator` (Push mode) |
| `mobile_app` | `token:software:totp` from Okta Verify | `microsoftAuthenticator` |
| `email` | `email` | `email` via emailMethods |
| `security_question` | `question` | N/A (deprecated in Entra) |
| `webauthn` | `webauthn` | `fido2` |
| `u2f` | `u2f` | Migrated to `fido2` |
| `duo` | `web` (Duo) | N/A (third-party integration) |
| `windows_hello` | N/A | `windowsHelloForBusiness` |
| `certificate` | N/A | `x509Certificate` or `certificateBasedAuth` |
| `temporary_access_pass` | N/A | `temporaryAccessPass` |

**Gap**: Okta supports more third-party factors (Duo, RSA, Symantec) that don't have Entra equivalents.

---

### Admin Role Detection

**Challenge**: Neither provider has a simple `is_admin` boolean. Detection requires checking role assignments.

#### Okta Approach
- **No direct API for "is admin"**
- **Inference method**: 
  1. Check if user appears in `GET /api/v1/users?filter=type.id eq "admin_type_id"` (if org uses admin user types)
  2. OR check assigned admin roles via `GET /api/v1/users/{id}/roles`
  3. Consider admin if user has ANY assigned role
- **Admin role types**: `SUPER_ADMIN`, `ORG_ADMIN`, `APP_ADMIN`, `USER_ADMIN`, `HELP_DESK_ADMIN`, `READ_ONLY_ADMIN`, `MOBILE_ADMIN`, `API_ACCESS_MANAGEMENT_ADMIN`, `REPORT_ADMIN`, `GROUP_MEMBERSHIP_ADMIN`

#### Entra ID Approach
- **Endpoint**: `GET /v1.0/users/{id}/memberOf` or `GET /v1.0/users/{id}/transitiveMemberOf`
- **OR**: `GET /v1.0/roleManagement/directory/roleAssignments?$filter=principalId eq '{userId}'`
- **Logic**: Check if user is member of any directory role or admin-privileged group
- **Common admin roles**: Global Administrator, User Administrator, Security Administrator, Conditional Access Administrator, etc.
- **Challenge**: Hundreds of possible roles; need to define which constitute "admin" for Leen's purposes

**Recommendation**: Maintain an allowlist of admin roles per provider that Leen considers "administrative" for security purposes.

**Need clarification**: Should Leen track granular role details or just boolean admin status?

---

### API Limitations & Restrictions

#### Okta
| Limitation | Impact |
|-----------|--------|
| Rate limits: 1000 req/min for users endpoint | Need request batching for large orgs |
| Factor enrollment only shows highest-priority policy | May not see all potential factors user could enroll |
| No built-in manager relationship | Cannot populate manager_id without custom profile attributes |
| `lastLogin` only updated on successful logins | Won't capture failed attempt times |
| Admin roles require separate API call | Adds latency for admin detection |

#### Microsoft Entra ID
| Limitation | Impact |
|-----------|--------|
| Default user query returns limited fields | Must use `$select` to get most attributes |
| MFA registration details in beta endpoint | Production dependency on unstable API |
| Sign-in activity requires Premium P1 or P2 | `last_sign_in` unavailable for basic licenses |
| Authentication methods per-user expensive | Bulk MFA status checking requires reports endpoint |
| Rate limits: 2000 req/10 min default | Slower than Okta for large tenant sync |
| Graph API throttling is complex | Token bucket + per-resource limits |
| Some attributes require `$expand` | Additional API calls for manager, groups |

---

## Policy Object Design

### Philosophy

The `policy` object represents organizational access control rules that apply to users. Key use cases:
1. **Compliance checks**: Verify strong password policies are enforced
2. **Access reviews**: Identify policies allowing unauthorized location access
3. **Risk assessment**: Detect weak authentication requirements
4. **Audit support**: Document policy configurations at points in time

### Policy Types to Normalize

Based on security investigation needs:

| Policy Type | Description | Okta Source | Entra Source |
|------------|-------------|-------------|--------------|
| **password** | Password strength, expiration, lockout rules | Password Policy | Password Protection + Password policies |
| **mfa_enrollment** | Which users/groups require MFA enrollment | MFA Enrollment Policy (Authenticator Enrollment) | Authentication Methods Policy |
| **sign_on** | Authentication requirements for sign-in | Sign-On Policy | Conditional Access Policies |
| **location** | Geographic or IP-based access restrictions | Sign-On Policy rules | Conditional Access (Named Locations) |

---

### Policy Object Schema

```json
{
  "id": "string",                    // Unique policy ID from provider
  "provider": "string",              // "okta" | "entra_id"
  "policy_type": "string",           // Normalized type (see Policy Type Mapping)
  "name": "string",                  // Display name
  "description": "string | null",    // Policy description
  "enabled": "boolean",              // Is policy active
  "priority": "number | null",       // Evaluation order (lower = higher priority)
  "created_at": "datetime",          // When policy was created
  "updated_at": "datetime",          // Last modification time
  "applies_to": {                    // Who the policy affects
    "users": ["string"],             // User IDs (empty = all users)
    "groups": ["string"],            // Group IDs  
    "everyone": "boolean"            // True if applies to all
  },
  "conditions": {                    // When policy applies
    "locations": {
      "included": ["string"],        // Allowed locations/IPs
      "excluded": ["string"]         // Blocked locations/IPs
    },
    "device_platforms": ["string"],  // "windows", "mac", "ios", "android", etc.
    "risk_levels": ["string"],       // "low", "medium", "high" (sign-in risk)
    "applications": ["string"]       // Which apps this applies to (if app-specific)
  },
  "requirements": {                  // What policy enforces
    "mfa_required": "boolean",
    "mfa_methods_allowed": ["string"], // Allowed MFA methods
    "password_complexity": {
      "min_length": "number | null",
      "require_lowercase": "boolean",
      "require_uppercase": "boolean",
      "require_numbers": "boolean",
      "require_symbols": "boolean",
      "excluded_characters": ["string"]
    },
    "password_age": {
      "max_age_days": "number | null",    // Force change after N days
      "min_age_minutes": "number | null",  // Minimum time before can change
      "history_count": "number | null"     // Can't reuse last N passwords
    },
    "lockout": {
      "enabled": "boolean",
      "max_attempts": "number | null",
      "lockout_duration_minutes": "number | null",
      "auto_unlock": "boolean"
    },
    "session": {
      "max_lifetime_hours": "number | null",
      "idle_timeout_minutes": "number | null",
      "persistent_cookie": "boolean | null"
    },
    "block_access": "boolean"        // Does policy block access entirely
  },
  "vendor_data": {}                  // Provider-specific fields
}
```

---

### Relevant API Endpoints for Policies

#### Okta - Password Policies
- **Endpoint**: `GET /api/v1/policies?type=PASSWORD`
- **Returns**: Password policies with rules
- **Fields of Interest**:
  - `conditions.people` → `applies_to`
  - `settings.password.complexity` → `requirements.password_complexity`
  - `settings.password.age` → `requirements.password_age`
  - `settings.password.lockout` → `requirements.lockout`

#### Okta - MFA Enrollment Policies
- **Endpoint**: `GET /api/v1/policies?type=MFA_ENROLL`
- **Returns**: Authenticator enrollment policies
- **Fields of Interest**:
  - `conditions.people` → `applies_to`
  - `settings.authenticators` or `settings.factors` → `requirements.mfa_methods_allowed`

#### Okta - Sign-On Policies
- **Endpoint**: `GET /api/v1/policies?type=OKTA_SIGN_ON`
- **Returns**: Sign-on policies with authentication rules
- **Fields of Interest**:
  - Policy rules contain MFA requirements, session settings, network zones
  - **Note**: Must call `GET /api/v1/policies/{policyId}/rules` for rule details
  - Rules have priority order and conditions (network, risk, etc.)

#### Entra ID - Conditional Access Policies
- **Endpoint**: `GET /v1.0/identity/conditionalAccess/policies`
- **Returns**: All conditional access policies
- **Fields of Interest**:
  - `conditions.users` → `applies_to.users`
  - `conditions.locations` → `conditions.locations`
  - `conditions.platforms` → `conditions.device_platforms`
  - `conditions.signInRiskLevels` → `conditions.risk_levels`
  - `grantControls.builtInControls` (contains "mfa") → `requirements.mfa_required`
  - `grantControls.operator` → determines if all or any control must be satisfied

#### Entra ID - Named Locations
- **Endpoint**: `GET /v1.0/identity/conditionalAccess/namedLocations`
- **Returns**: Configured network locations (countries, IP ranges)
- **Usage**: Referenced by conditional access policies

#### Entra ID - Authentication Methods Policy
- **Endpoint**: `GET /beta/policies/authenticationMethodsPolicy`
- **Returns**: Which auth methods are enabled org-wide
- **Note**: This is org-level, not per-user group policy like Okta

**Need clarification**: Entra password policies are set per-domain, not via Graph API in same way as Okta. Should we query Azure AD Domain Services config or rely on tenant-wide settings?

---

### Policy Field Mappings

#### Password Policy

| Leen Field | Okta Source | Entra ID Source | Notes |
|-----------|-------------|-----------------|-------|
| `policy_type` | "PASSWORD" → "password" | Derived from domain config → "password" | Normalized value |
| `name` | `name` | Constructed: "Password Policy for {domain}" | Entra doesn't have named password policies in Graph |
| `enabled` | `status === "ACTIVE"` | Assumed true for tenant | - |
| `priority` | `priority` | N/A (no priority in Entra) | - |
| `applies_to.groups` | `conditions.people.groups.include` | All users (tenant-wide) | Okta supports group targeting |
| `requirements.password_complexity.min_length` | `settings.password.complexity.minLength` | Via Microsoft Admin Portal or Azure AD Connect | **Gap**: Not in Graph API v1.0 |
| `requirements.password_complexity.require_lowercase` | `settings.password.complexity.minLowerCase > 0` | Tenant password policy | - |
| `requirements.password_complexity.require_uppercase` | `settings.password.complexity.minUpperCase > 0` | Tenant password policy | - |
| `requirements.password_complexity.require_numbers` | `settings.password.complexity.minNumber > 0` | Tenant password policy | - |
| `requirements.password_complexity.require_symbols` | `settings.password.complexity.minSymbol > 0` | Tenant password policy | - |
| `requirements.password_age.max_age_days` | `settings.password.age.maxAgeDays` | Via domain config (not Graph) | - |
| `requirements.lockout.max_attempts` | `settings.password.lockout.maxAttempts` | Smart Lockout settings (not readily via Graph) | **Gap**: Entra uses smart lockout, not simple threshold |

**Need clarification**: How should Leen handle Entra's password policies not being available via Graph API v1.0? Options:
1. Skip password policy object for Entra
2. Require admin portal config export
3. Use defaults + note unavailability in metadata

---

#### MFA Enrollment Policy

| Leen Field | Okta Source | Entra ID Source | Notes |
|-----------|-------------|-----------------|-------|
| `policy_type` | "MFA_ENROLL" → "mfa_enrollment" | "Authentication Methods Policy" → "mfa_enrollment" | - |
| `name` | `name` | `authenticationMethodsPolicy.displayName` or default | - |
| `enabled` | `status === "ACTIVE"` | Method-specific `state === "enabled"` | Entra enables per-method, not policy-level |
| `applies_to.groups` | `conditions.people.groups.include` | Per-method configuration targets | Different granularity |
| `requirements.mfa_methods_allowed` | Extract from `settings.factors` or `settings.authenticators` | Extract from `registrationEnforcement.authenticationMethodsRegistrationCampaign.includeTargets` | Must aggregate across method configs |

**Mapping challenge**: Okta has holistic MFA enrollment policies; Entra configures per authentication method. Need to synthesize Entra's per-method configs into policy-like objects.

**Recommendation**: Create one policy object per enabled authentication method in Entra, or create a synthetic "MFA Enrollment" policy that aggregates all methods.

---

#### Sign-On / Conditional Access Policy

| Leen Field | Okta Source | Entra ID Source | Notes |
|-----------|-------------|-----------------|-------|
| `policy_type` | "OKTA_SIGN_ON" → "sign_on" | "Conditional Access" → "sign_on" | - |
| `name` | `name` | `displayName` | - |
| `enabled` | `status === "ACTIVE"` | `state === "enabled"` | - |
| `applies_to.users` | `conditions.people.users.include` | `conditions.users.includeUsers` | Entra uses GUIDs |
| `applies_to.groups` | `conditions.people.groups.include` | `conditions.users.includeGroups` | - |
| `applies_to.everyone` | Check if "All Users" in include | `conditions.users.includeUsers` contains "All" | - |
| `conditions.locations.included` | From policy rules' `network.include` (zone IDs) | `conditions.locations.includeLocations` (named location IDs) | Need to resolve zone/location names |
| `conditions.locations.excluded` | From policy rules' `network.exclude` | `conditions.locations.excludeLocations` | - |
| `conditions.device_platforms` | N/A in sign-on policy | `conditions.platforms.includePlatforms` | Okta doesn't filter by platform in sign-on |
| `conditions.risk_levels` | From behavior detection config (separate) | `conditions.signInRiskLevels` | Entra integrates risk directly |
| `requirements.mfa_required` | From policy rules' `factorMode` | `grantControls.builtInControls` contains "mfa" | - |
| `requirements.session.max_lifetime_hours` | From rules' `session.maxSessionLifetimeMinutes` / 60 | `sessionControls.signInFrequency` | - |
| `requirements.block_access` | Rules can have action "DENY" | `grantControls.builtInControls` contains "block" | - |

---

### Location Mapping Sub-Challenge

Both providers reference locations by ID; must dereference:

#### Okta Network Zones
- **Endpoint**: `GET /api/v1/zones`
- **Contains**: IP ranges, geographies, system zones (like "Any Location")
- **Link**: Sign-on policy rules reference zone IDs

#### Entra Named Locations
- **Endpoint**: `GET /v1.0/identity/conditionalAccess/namedLocations`
- **Types**: `ipNamedLocation` (IP ranges), `countryNamedLocation` (country codes)
- **Link**: Conditional access policies reference location IDs

**Recommendation**: Leen should maintain a cache of location definitions and resolve IDs to human-readable names in policy objects.

---

### Groups and Applications Resolution

Policies reference groups and applications by ID; consider:

**Options:**
1. **Store IDs only** in policy objects (leaner, but less useful)
2. **Resolve and embed names** (requires additional API calls)
3. **Provide separate endpoints** for `/idp/groups` and `/idp/applications` that policies can reference

**Recommendation**: Store IDs in policy objects, provide separate IDP Groups and Applications endpoints. This follows Leen's pattern in other models (e.g., device groups in VMS).

---

### Handling Policy Rules in Okta

Okta policies contain rules that define specific conditions and actions. A single policy can have multiple rules evaluated in priority order.

**Design decision for Leen:**

**Option A**: Flatten rules into separate policy objects
- Each Okta rule becomes a distinct Leen policy
- Pros: Simpler schema, clearer evaluation logic
- Cons: Loses hierarchical relationship, more policy objects

**Option B**: Store rules as nested array in policy object
- Add `rules` array to policy schema
- Pros: Preserves hierarchy, matches Okta structure
- Cons: More complex queries, schema diverges from Entra

**Option C**: Create parent-child relationship
- Add `parent_policy_id` field, link rules to parent policy
- Pros: Maintains relationship, allows independent querying
- Cons: Requires understanding of relationships

**Recommendation**: Option A (flatten rules) for consistency with Entra's flat conditional access model. Store original policy ID in `vendor_data.parent_policy_id` for reference.

---

### API Limitations for Policies

#### Okta Policy API
| Limitation | Impact |
|-----------|--------|
| Rules require separate API call per policy | Need to fetch `/policies/{id}/rules` for each policy |
| Network zones referenced by ID | Must resolve via `/zones` endpoint |
| Some policy types have different schemas | Need type-specific parsing logic |
| Rate limit: 100 req/min | Slower for orgs with many policies |

#### Entra ID Conditional Access
| Limitation | Impact |
|-----------|--------|
| No password policy API in Graph v1.0 | Cannot retrieve password requirements programmatically |
| Authentication methods in beta | Production reliance on unstable endpoint |
| Named locations require separate fetch | Must call `/namedLocations` to resolve location names |
| Group/app IDs not expanded by default | Need additional calls or accept IDs only |
| Conditional Access requires Premium P1 | Feature may not be available in all tenants |

---

## Implementation Recommendations

### 1. Data Collection Strategy

**For User Object:**
```
1. Fetch base user data (GET /users)
2. For Okta: Fetch MFA factors (GET /users/{id}/factors) - can batch with async calls
3. For Entra: Use bulk report endpoint (GET /beta/reports/credentialUserRegistrationDetails) if available
4. For admin detection: Batch role lookups or filter user lists
5. Cache user type definitions (Okta) to reduce API calls
```

**For Policy Object:**
```
1. Fetch all policies by type (Okta: append ?type=X; Entra: get by endpoint)
2. For Okta: Fetch rules for each policy (GET /policies/{id}/rules)
3. Fetch supporting data: network zones (Okta), named locations (Entra)
4. Optionally: Resolve group and app IDs to names
5. Transform and normalize to Leen schema
```

### 2. Sync Frequency Considerations

| Data Type | Recommended Sync | Rationale |
|-----------|------------------|-----------|
| User base attributes | Every 6-24 hours | Changes infrequently |
| User status | Every 1-4 hours | Supports timely deprovisioning detection |
| MFA enrollment | Every 6-24 hours | Changes when users enroll/unenroll |
| Admin roles | Every 4-12 hours | Important for security but changes rarely |
| Policies | Every 24 hours or on-demand | Very infrequent changes |
| Policy targeting (users/groups) | Every 12-24 hours | May change as org structure evolves |

### 3. Error Handling

**Common Scenarios:**

| Scenario | Handling Strategy |
|----------|------------------|
| User has no MFA factors endpoint access | Set `mfa_status: "unavailable"`, log permission issue |
| Entra sign-in activity not available (no Premium) | Set `last_sign_in: null`, add to `vendor_data.limitations` |
| Rate limit exceeded | Implement exponential backoff, prioritize critical data |
| Beta endpoint unavailable | Fall back to alternative method, document limitation |
| Policy references deleted group | Include ID in policy, mark as `unresolved_reference` in metadata |

### 4. Permission Requirements Summary

**Minimum Required Permissions:**

**Okta:**
- `okta.users.read` - User data and factors
- `okta.policies.read` - Policy data  
- `okta.zones.read` - Network zones
- `okta.schemas.read` - User type schemas (if using types)

**Microsoft Entra ID:**
- `User.Read.All` - Basic user data
- `UserAuthenticationMethod.Read.All` - MFA methods
- `Reports.Read.All` - MFA registration reports
- `Policy.Read.All` - Conditional access policies
- `RoleManagement.Read.Directory` - Admin role detection (optional)

**Need clarification**: Should Leen document "minimal" vs "recommended" permission sets?

---

## Gap Analysis Summary

### Fields We Cannot Reliably Derive

| Field | Okta Challenge | Entra Challenge | Proposed Solution |
|-------|----------------|-----------------|-------------------|
| `manager_id` | Not in default schema | Requires $expand or separate call | Make nullable, fetch if available |
| `is_admin` | No direct boolean | No direct boolean | Infer from roles, document logic |
| `last_sign_in` | Only on successful login | Requires Premium license | Make nullable, note limitation |
| Password policy details | Available via API | Not in Graph API v1.0 | Document Entra limitation, focus on Okta |
| Smart lockout details | Available | Not easily via Graph | Document as Entra gap |

### Data Model Inconsistencies

| Challenge | Description | Recommendation |
|-----------|-------------|----------------|
| Policy vs Rules | Okta uses policy-rule hierarchy; Entra uses flat policies | Flatten Okta rules to match Entra |
| MFA granularity | Okta has policies; Entra configures per-method | Create synthetic policies for Entra |
| User types | Okta has formal types; Entra has userType string (often null) | Map both to string, accept nulls |
| Status model | Different lifecycle states | Create normalized status enum |
| Location model | Different IP/geo formats | Maintain location objects, reference by ID |

### Provider-Specific Features

**Okta-only:**
- Recovery questions (deprecated in Entra)
- User type schemas
- Delegated authentication providers
- More granular factor types

**Entra-only:**
- Sign-in risk levels
- Device platform conditions  
- Temporary Access Pass
- Certificate-based auth

**Recommendation**: Support provider-specific features via `vendor_data` object, normalize only common capabilities.

---

## Testing Recommendations

### Validation Checklist

**User Object:**
- [ ] Verify user status mapping covers all Okta statuses
- [ ] Test MFA detection with users having 0, 1, and multiple factors
- [ ] Validate admin detection against known admin and non-admin users
- [ ] Confirm null handling for optional fields (manager, secondary email, etc.)
- [ ] Test with guest users (Entra) and federated users (both)

**Policy Object:**
- [ ] Verify all policy types can be fetched and parsed
- [ ] Test rule flattening with complex multi-rule Okta policies
- [ ] Validate location ID resolution for both providers
- [ ] Confirm handling of disabled/archived policies
- [ ] Test with tenants lacking Premium features (Entra)

**Edge Cases:**
- [ ] Users with no login history
- [ ] Policies with empty targeting (should affect everyone)
- [ ] Deleted groups still referenced in policies
- [ ] Rate limit handling under load
- [ ] Partial permission grants (e.g., read users but not factors)

---

## Sample API Responses

### Okta User with MFA
```json
{
  "id": "00u1a2b3c4d5e6f7g8h9",
  "status": "ACTIVE",
  "created": "2024-01-15T10:30:00.000Z",
  "lastLogin": "2024-10-23T14:22:00.000Z",
  "passwordChanged": "2024-08-01T09:15:00.000Z",
  "profile": {
    "login": "jdoe@company.com",
    "email": "jdoe@company.com",
    "firstName": "John",
    "lastName": "Doe",
    "title": "Senior Engineer",
    "department": "Engineering",
    "employeeNumber": "E12345"
  },
  "type": {
    "id": "oty1a2b3c4d5e6f7g8"
  }
}
```

### Okta User Factors Response
```json
[
  {
    "id": "mfa1a2b3c4d5e6f7g8",
    "factorType": "token:software:totp",
    "provider": "OKTA",
    "status": "ACTIVE",
    "created": "2024-02-10T08:00:00.000Z"
  },
  {
    "id": "mfa9h8g7f6e5d4c3b2",
    "factorType": "push",
    "provider": "OKTA",
    "status": "ACTIVE",
    "created": "2024-02-10T08:05:00.000Z"
  }
]
```

### Entra User Response
```json
{
  "id": "a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6",
  "userPrincipalName": "jdoe@company.com",
  "displayName": "John Doe",
  "givenName": "John",
  "surname": "Doe",
  "mail": "jdoe@company.com",
  "jobTitle": "Senior Engineer",
  "department": "Engineering",
  "employeeId": "E12345",
  "accountEnabled": true,
  "createdDateTime": "2024-01-15T10:30:00Z",
  "userType": "Member"
}
```

### Entra MFA Registration Details
```json
{
  "id": "a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6",
  "userPrincipalName": "jdoe@company.com",
  "isMfaRegistered": true,
  "isMfaCapable": true,
  "methodsRegistered": ["mobilePhone", "microsoftAuthenticatorPush"],
  "defaultMfaMethod": "microsoftAuthenticatorPush"
}
```

### Okta Password Policy
```json
{
  "id": "pol1a2b3c4d5e6f7g8",
  "type": "PASSWORD",
  "name": "Default Password Policy",
  "status": "ACTIVE",
  "priority": 1,
  "conditions": {
    "people": {
      "groups": {
        "include": ["00g1a2b3c4d5e6f7g8"]
      }
    }
  },
  "settings": {
    "password": {
      "complexity": {
        "minLength": 12,
        "minLowerCase": 1,
        "minUpperCase": 1,
        "minNumber": 1,
        "minSymbol": 1
      },
      "age": {
        "maxAgeDays": 90,
        "minAgeMinutes": 0,
        "historyCount": 5
      },
      "lockout": {
        "maxAttempts": 5,
        "autoUnlockMinutes": 30
      }
    }
  }
}
```

### Entra Conditional Access Policy
```json
{
  "id": "a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6",
  "displayName": "Require MFA for All Users",
  "state": "enabled",
  "conditions": {
    "users": {
      "includeUsers": ["All"]
    },
    "applications": {
      "includeApplications": ["All"]
    },
    "signInRiskLevels": ["medium", "high"]
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["mfa"]
  },
  "sessionControls": {
    "signInFrequency": {
      "value": 8,
      "type": "hours"
    }
  }
}
```

---

## Normalized Leen Objects (Examples)

### Leen User Object (from Okta)
```json
{
  "id": "00u1a2b3c4d5e6f7g8h9",
  "provider": "okta",
  "user_principal_name": "jdoe@company.com",
  "email": "jdoe@company.com",
  "display_name": "John Doe",
  "first_name": "John",
  "last_name": "Doe",
  "status": "active",
  "user_type": "employee",
  "job_title": "Senior Engineer",
  "department": "Engineering",
  "employee_id": "E12345",
  "manager_id": null,
  "is_admin": false,
  "created_at": "2024-01-15T10:30:00.000Z",
  "last_sign_in": "2024-10-23T14:22:00.000Z",
  "mfa_enrolled": true,
  "mfa_methods": ["totp", "push_notification"],
  "mfa_status": "registered",
  "last_password_change": "2024-08-01T09:15:00.000Z",
  "account_locked": false,
  "vendor_data": {
    "okta": {
      "type_id": "oty1a2b3c4d5e6f7g8",
      "activated": "2024-01-15T10:32:00.000Z",
      "status_changed": "2024-01-15T10:32:00.000Z"
    }
  }
}
```

### Leen Policy Object (from Okta Password Policy)
```json
{
  "id": "pol1a2b3c4d5e6f7g8",
  "provider": "okta",
  "policy_type": "password",
  "name": "Default Password Policy",
  "description": null,
  "enabled": true,
  "priority": 1,
  "created_at": "2024-01-01T00:00:00.000Z",
  "updated_at": "2024-09-15T10:20:00.000Z",
  "applies_to": {
    "users": [],
    "groups": ["00g1a2b3c4d5e6f7g8"],
    "everyone": false
  },
  "conditions": {
    "locations": {
      "included": [],
      "excluded": []
    },
    "device_platforms": [],
    "risk_levels": [],
    "applications": []
  },
  "requirements": {
    "mfa_required": false,
    "mfa_methods_allowed": [],
    "password_complexity": {
      "min_length": 12,
      "require_lowercase": true,
      "require_uppercase": true,
      "require_numbers": true,
      "require_symbols": true,
      "excluded_characters": []
    },
    "password_age": {
      "max_age_days": 90,
      "min_age_minutes": 0,
      "history_count": 5
    },
    "lockout": {
      "enabled": true,
      "max_attempts": 5,
      "lockout_duration_minutes": 30,
      "auto_unlock": true
    },
    "session": {
      "max_lifetime_hours": null,
      "idle_timeout_minutes": null,
      "persistent_cookie": null
    },
    "block_access": false
  },
  "vendor_data": {
    "okta": {
      "policy_type": "PASSWORD",
      "system_policy": false
    }
  }
}
```

### Leen Policy Object (from Entra Conditional Access)
```json
{
  "id": "a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6",
  "provider": "entra_id",
  "policy_type": "sign_on",
  "name": "Require MFA for All Users",
  "description": null,
  "enabled": true,
  "priority": null,
  "created_at": "2024-03-01T12:00:00.000Z",
  "updated_at": "2024-08-15T09:30:00.000Z",
  "applies_to": {
    "users": [],
    "groups": [],
    "everyone": true
  },
  "conditions": {
    "locations": {
      "included": [],
      "excluded": []
    },
    "device_platforms": [],
    "risk_levels": ["medium", "high"],
    "applications": []
  },
  "requirements": {
    "mfa_required": true,
    "mfa_methods_allowed": [],
    "password_complexity": null,
    "password_age": null,
    "lockout": null,
    "session": {
      "max_lifetime_hours": 8,
      "idle_timeout_minutes": null,
      "persistent_cookie": null
    },
    "block_access": false
  },
  "vendor_data": {
    "entra_id": {
      "grant_controls_operator": "OR",
      "built_in_controls": ["mfa"],
      "include_applications": ["All"]
    }
  }
}
```

---

## Open Questions Requiring Clarification

1. **Entra Password Policies**: Since password policies are not available via Graph API v1.0, should Leen:
   - Skip password policy objects for Entra entirely?
   - Require manual configuration input?
   - Document as a known limitation and only support Okta?

2. **Admin Role Granularity**: Should the normalized model include:
   - Just a boolean `is_admin` flag?
   - An array of specific admin roles?
   - A single `primary_admin_role` field?

3. **Beta Endpoint Dependencies**: Is Leen comfortable depending on Microsoft's beta endpoints for MFA registration data, or should we:
   - Use only v1.0 endpoints (limiting functionality)?
   - Use beta but document the risk?
   - Implement fallback logic?

4. **Sync Strategy for Manager Relationships**: Should Leen fetch manager data:
   - Always (adds API call overhead)?
   - Only when explicitly requested via query parameter?
   - During initial sync but not incremental updates?

5. **Policy Rule Flattening**: Confirm preference for flattening Okta rules into separate policy objects vs. maintaining hierarchy.

6. **Location Resolution**: Should location IDs in policy objects be:
   - Resolved to names inline (requires caching)?
   - Kept as IDs with separate location endpoint?
   - Both (ID + name embedded)?

7. **Guest Users in Entra**: How should Leen handle B2B guest users? They have different attribute sets and behaviors.

8. **MFA Status for Users with Conditional Access-Only Requirements**: If Entra requires MFA via conditional access but user hasn't enrolled methods, what should `mfa_status` be?

---

## Conclusion

This mapping provides a comprehensive approach to normalizing Okta and Microsoft Entra ID data into Leen's IDP model. The design prioritizes:

1. **Security investigation utility**: Fields chosen specifically for access reviews and incident response
2. **Cross-provider consistency**: Normalized schema works for both IDPs despite architectural differences
3. **Practical implementation**: Acknowledges API limitations and proposes concrete solutions
4. **Extensibility**: `vendor_data` allows provider-specific details without polluting normalized schema

The major challenges involve:
- Entra's limited Graph API for password policies
- Different mental models for policies (hierarchical vs. flat)
- MFA data requiring different endpoints per provider
- Admin role detection requiring inference

**Next steps** would involve:
1. Resolving open questions via stakeholder discussion
2. Building prototype integration with test tenants
3. Validating normalized schema with real-world security use cases
4. Documenting API permission requirements for customer setup
5. Creating migration path for existing Leen customers

---

## Appendix: Complete Field Reference

### User Object - Complete Field List

| Field Name | Type | Required | Description |
|------------|------|----------|-------------|
| id | string | Yes | Provider's unique user identifier |
| provider | string | Yes | "okta" or "entra_id" |
| user_principal_name | string | Yes | Primary login identifier |
| email | string | Yes | Primary email address |
| display_name | string | No | Full name for display |
| first_name | string | No | Given name |
| last_name | string | No | Family name/surname |
| status | string | Yes | Normalized status (see Status Mapping) |
| user_type | string | No | User classification (employee, contractor, guest) |
| job_title | string | No | Position title |
| department | string | No | Organizational department |
| employee_id | string | No | Employee number/identifier |
| manager_id | string | No | User ID of direct manager |
| is_admin | boolean | Yes | Whether user has admin privileges |
| created_at | datetime | Yes | Account creation timestamp |
| last_sign_in | datetime | No | Most recent successful login |
| mfa_enrolled | boolean | Yes | Whether user has enrolled MFA |
| mfa_methods | array[string] | Yes | List of enrolled MFA methods |
| mfa_status | string | Yes | Registration status (see MFA Status Mapping) |
| last_password_change | datetime | No | When password was last updated |
| account_locked | boolean | Yes | Whether account is locked |
| vendor_data | object | No | Provider-specific additional fields |

### Policy Object - Complete Field List

| Field Name | Type | Required | Description |
|------------|------|----------|-------------|
| id | string | Yes | Provider's unique policy identifier |
| provider | string | Yes | "okta" or "entra_id" |
| policy_type | string | Yes | Normalized type (password, mfa_enrollment, sign_on, location) |
| name | string | Yes | Policy display name |
| description | string | No | Policy description |
| enabled | boolean | Yes | Whether policy is active |
| priority | number | No | Evaluation priority (lower = higher priority) |
| created_at | datetime | Yes | Policy creation timestamp |
| updated_at | datetime | Yes | Last modification timestamp |
| applies_to | object | Yes | Targeting information |
| applies_to.users | array[string] | Yes | User IDs (empty = not user-targeted) |
| applies_to.groups | array[string] | Yes | Group IDs (empty = not group-targeted) |
| applies_to.everyone | boolean | Yes | True if applies to all users |
| conditions | object | Yes | When policy applies |
| conditions.locations | object | Yes | Location-based conditions |
| conditions.locations.included | array[string] | Yes | Allowed location IDs |
| conditions.locations.excluded | array[string] | Yes | Blocked location IDs |
| conditions.device_platforms | array[string] | Yes | Platform conditions |
| conditions.risk_levels | array[string] | Yes | Risk level conditions |
| conditions.applications | array[string] | Yes | Application IDs (empty = all apps) |
| requirements | object | Yes | What policy enforces |
| requirements.mfa_required | boolean | Yes | Whether MFA is required |
| requirements.mfa_methods_allowed | array[string] | Yes | Permitted MFA methods |
| requirements.password_complexity | object | No | Password complexity rules |
| requirements.password_age | object | No | Password age policies |
| requirements.lockout | object | No | Account lockout settings |
| requirements.session | object | No | Session management settings |
| requirements.block_access | boolean | Yes | Whether policy blocks access |
| vendor_data | object | No | Provider-specific additional fields |

---
