/*
 * Copyright 2012-2025 CodeLibs Project and the Others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */
package org.codelibs.fess.sso.saml;

import java.util.List;
import java.util.Set;

import org.apache.logging.log4j.Level;
import org.codelibs.core.misc.DynamicProperties;
import org.codelibs.fess.sso.saml.SamlCredential.SamlUser;
import org.codelibs.fess.unit.LogCapturingAppender;
import org.codelibs.fess.util.ComponentUtil;
import org.dbflute.utflute.mocklet.MockletHttpServletRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.lastaflute.web.login.credential.LoginCredential;

/**
 * The login from end to end: the authenticator starts it, the identity provider of {@link TestIdp} answers with a
 * signed (and sometimes encrypted) response, and the authenticator reads the user out of it.
 */
public class SamlLoginTest extends SamlTestCase {

    /** Starts a login and posts the response that answers it. */
    private LoginCredential login(final SamlAuthenticator authenticator, final MockletHttpServletRequest request,
            final java.util.function.Consumer<TestIdp.ResponseSpec> tweak) {
        final String requestId = startLogin(authenticator, request);
        post(request, signedResponse(requestId, tweak));
        return authenticator.getLoginCredential();
    }

    private static SamlUser userOf(final LoginCredential credential) {
        Assertions.assertInstanceOf(SamlCredential.class, credential);
        return ((SamlCredential) credential).getUser();
    }

    @Test
    public void test_postWithAValidResponseLogsTheUserIn() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        final MockletHttpServletRequest request = getMockRequest();
        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            final String requestId = startLogin(authenticator, request);
            post(request, signedResponse(requestId, null));

            final LoginCredential credential = authenticator.getLoginCredential();

            assertTrue(String.valueOf(credential), credential instanceof SamlCredential);
            assertEquals(USER, ((SamlCredential) credential).getUserId());
            final SamlUser user = ((SamlCredential) credential).getUser();
            assertEquals(USER, user.getName());
            assertEquals("_session1", user.getSessionIndex());
            assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", user.getNameIdFormat());
            // memberOf is the attribute the groups come from unless another one is named
            Assertions.assertArrayEquals(new String[] { "staff", "dev" }, user.getGroupNames());
            Assertions.assertArrayEquals(new String[0], user.getRoleNames());
            // the ID is consumed: the same response cannot log in again
            assertTrue(String.valueOf(pendingRequestIds(request.getSession(false))),
                    pendingRequestIds(request.getSession(false)).isEmpty());
            assertTrue(String.valueOf(appender.warnings()), appender.warnings().isEmpty());
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_groupsAndRolesComeFromTheConfiguredAttributes() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        final DynamicProperties systemProperties = ComponentUtil.getSystemProperties();
        systemProperties.setProperty("saml.attribute.group.name", "groups");
        systemProperties.setProperty("saml.attribute.role.name", "roles");
        systemProperties.setProperty("saml.default.groups", "user");
        systemProperties.setProperty("saml.default.roles", "viewer, ");

        final LoginCredential credential = login(authenticator, getMockRequest(), spec -> {
            spec.attributes.clear();
            spec.attributes.put("groups", List.of("g1", "g2"));
            spec.attributes.put("roles", List.of("r1"));
            spec.attributes.put("memberOf", List.of("not-a-group-here"));
        });

        final SamlUser user = userOf(credential);
        Assertions.assertArrayEquals(new String[] { "g1", "g2", "user" }, user.getGroupNames());
        Assertions.assertArrayEquals(new String[] { "r1", "viewer" }, user.getRoleNames());
    }

    @Test
    public void test_groupsAndRolesFallBackToTheDefaultsWithoutAttributes() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        final DynamicProperties systemProperties = ComponentUtil.getSystemProperties();
        systemProperties.setProperty("saml.default.groups", "user");
        systemProperties.setProperty("saml.default.roles", "viewer");

        // the IdP releases no attributes at all
        final LoginCredential credential = login(authenticator, getMockRequest(), spec -> spec.attributes.clear());

        final SamlUser user = userOf(credential);
        Assertions.assertArrayEquals(new String[] { "user" }, user.getGroupNames());
        Assertions.assertArrayEquals(new String[] { "viewer" }, user.getRoleNames());
    }

    @Test
    public void test_anEncryptedAssertionLogsTheUserIn() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        final DynamicProperties systemProperties = ComponentUtil.getSystemProperties();
        systemProperties.setProperty("saml.sp.x509cert", TestIdp.pem("sp"));
        systemProperties.setProperty("saml.sp.privatekey", TestIdp.keyPem("sp"));
        systemProperties.setProperty("saml.security.want_assertions_encrypted", "true");

        final LoginCredential credential = login(authenticator, getMockRequest(), spec -> spec.encryption = "gcm");

        assertEquals(USER, ((SamlCredential) credential).getUserId());
        Assertions.assertArrayEquals(new String[] { "staff", "dev" }, userOf(credential).getGroupNames());
    }

    @Test
    public void test_aPlainAssertionIsRefusedWhenEncryptionIsRequired() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        final DynamicProperties systemProperties = ComponentUtil.getSystemProperties();
        systemProperties.setProperty("saml.sp.privatekey", TestIdp.keyPem("sp"));
        systemProperties.setProperty("saml.security.want_assertions_encrypted", "true");
        final MockletHttpServletRequest request = getMockRequest();
        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            assertNull(login(authenticator, request, null));

            assertEquals(1, appender.warnings().size(), String.valueOf(appender.warnings()));
            assertTrue(appender.warnings().get(0), appender.warnings().get(0).startsWith("Authentication failed: UNSUPPORTED - "));
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_anUnsignedResponseIsRefused() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        final MockletHttpServletRequest request = getMockRequest();
        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            final LoginCredential credential = login(authenticator, request, spec -> {
                spec.signResponse = false;
                spec.signAssertion = false;
            });

            assertNull(credential);
            assertEquals(1, appender.warnings().size(), String.valueOf(appender.warnings()));
            assertTrue(appender.warnings().get(0), appender.warnings().get(0).startsWith("Authentication failed: NOT_SIGNED - "));
            // the login is still waiting for a response that is signed
            assertEquals(1, pendingRequestIds(request.getSession(false)).size());
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_aResponseForAnUnknownRequestIsRefusedWithoutAStackTrace() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        final MockletHttpServletRequest request = getMockRequest();
        final String requestId = startLogin(authenticator, request);
        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            // an IdP-initiated response, or one meant for a login of another session
            post(request, signedResponse("_started_elsewhere", null));

            assertNull(authenticator.getLoginCredential());

            assertEquals(1, appender.warnings().size(), String.valueOf(appender.warnings()));
            assertTrue(appender.warnings().get(0), appender.warnings().get(0).contains("no matching AuthnRequest ID"));
            assertTrue(appender.warnings().get(0), appender.warnings().get(0).contains("(1 pending)"));
            appender.eventsAt(Level.WARN).forEach(e -> assertNull(e.getThrown(), String.valueOf(e.getThrown())));
            // and the login that is in flight is not burnt by it
            Assertions.assertEquals(Set.of(requestId), pendingRequestIds(request.getSession(false)));
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_theSameResponseCannotLogInTwice() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        final MockletHttpServletRequest request = getMockRequest();
        final String requestId = startLogin(authenticator, request);
        final String response = signedResponse(requestId, null);
        post(request, response);
        assertNotNull(authenticator.getLoginCredential(), "the first POST logs in");

        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            // the browser posts the same form again
            post(request, response);

            assertNull(authenticator.getLoginCredential());

            assertEquals(1, appender.warnings().size(), String.valueOf(appender.warnings()));
            assertTrue(appender.warnings().get(0), appender.warnings().get(0).contains("no matching AuthnRequest ID"));
            appender.eventsAt(Level.WARN).forEach(e -> assertNull(e.getThrown(), String.valueOf(e.getThrown())));
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_aReplayedAssertionIsRefusedEvenWhenItsRequestIdIsPendingAgain() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        final MockletHttpServletRequest request = getMockRequest();
        final String requestId = startLogin(authenticator, request);
        final String response = signedResponse(requestId, null);
        post(request, response);
        assertNotNull(authenticator.getLoginCredential(), "the first POST logs in");
        // another node, or a stale copy of the session, still holds the ID
        addPendingRequestId(request.getSession(false), requestId);

        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            assertNull(authenticator.getLoginCredential());

            assertEquals(1, appender.warnings().size(), String.valueOf(appender.warnings()));
            assertTrue(appender.warnings().get(0), appender.warnings().get(0).startsWith("Authentication failed: REPLAYED - "));
            appender.eventsAt(Level.WARN).forEach(e -> assertNull(e.getThrown(), String.valueOf(e.getThrown())));
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_theReplayCacheSurvivesAChangeOfTheSettings() throws Exception {
        // The service provider is rebuilt whenever an administrator saves a SAML setting. The
        // replay cache is the one thing that must not be rebuilt with it, or an assertion already
        // seen could be used again at the moment a setting is saved.
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        final MockletHttpServletRequest request = getMockRequest();
        final String requestId = startLogin(authenticator, request);
        post(request, signedResponse(requestId, null));
        final org.codelibs.saml4j.ServiceProvider before = authenticator.getServiceProvider();
        assertNotNull(authenticator.getLoginCredential(), "the first POST logs in");

        ComponentUtil.getSystemProperties().setProperty("saml.security.clock_drift", "121");
        Assertions.assertNotSame(before, authenticator.getServiceProvider());
        addPendingRequestId(request.getSession(false), requestId);

        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            assertNull(authenticator.getLoginCredential());

            assertEquals(1, appender.warnings().size(), String.valueOf(appender.warnings()));
            assertTrue(appender.warnings().get(0), appender.warnings().get(0).startsWith("Authentication failed: REPLAYED - "));
        } finally {
            appender.detach();
        }
    }
}
