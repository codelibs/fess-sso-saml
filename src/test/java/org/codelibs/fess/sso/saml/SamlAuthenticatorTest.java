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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LogEvent;
import org.codelibs.core.lang.StringUtil;
import org.codelibs.core.misc.DynamicProperties;
import org.codelibs.fess.app.web.base.login.ActionResponseCredential;
import org.codelibs.fess.exception.SsoLoginException;
import org.codelibs.fess.exception.SsoMessageException;
import org.codelibs.fess.mylasta.action.FessMessages;
import org.codelibs.fess.exception.SsoStateException;
import org.codelibs.fess.mylasta.action.FessUserBean;
import org.codelibs.fess.sso.SsoResponseType;
import org.codelibs.fess.sso.saml.SamlCredential.SamlUser;
import org.codelibs.fess.unit.LogCapturingAppender;
import org.codelibs.fess.util.ComponentUtil;
import org.codelibs.saml4j.SamlConfig;
import org.codelibs.saml4j.ServiceProvider;
import org.dbflute.optional.OptionalThing;
import org.dbflute.utflute.mocklet.MockletHttpServletRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.lastaflute.web.login.credential.LoginCredential;
import org.lastaflute.web.response.ActionResponse;
import org.lastaflute.web.response.StreamResponse;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

public class SamlAuthenticatorTest extends SamlTestCase {

    private static final String SESSION_MARKER = "SLO_TEST_MARKER";

    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";

    /**
     * A StatusCode value as a sender can write it: character references survive XML attribute-value
     * normalisation, so CR, LF, NEL, LS and PS reach the library intact, followed by enough filler to show the
     * length is not bounded either.
     */
    private static final String FORGED_STATUS_CODE = "urn:x&#13;&#10;WARN forged line&#x85;&#x2028;&#x2029;end" + "A".repeat(5000);

    /** A SAMLResponse that is not base64 at all, the cheapest payload an anonymous client can send. */
    private static final String NOT_BASE64 = "!!! not base64 at all !!!";

    /** A SAMLResponse that decodes cleanly and is then not parsable as XML. */
    private static final String BROKEN_XML = Base64.getEncoder().encodeToString("<samlp:Response".getBytes(StandardCharsets.UTF_8));

    private static List<String> warnings(final LogCapturingAppender appender) {
        return appender.warnings();
    }

    /** Asserts that a log or exception text cannot start a new log line and is not unbounded. */
    private void assertSafeForLog(final String text, final int maxLength) {
        for (final char c : text.toCharArray()) {
            assertFalse("control or line-break character U+" + Integer.toHexString(c) + " in: " + text,
                    Character.isISOControl(c) || c == ' ' || c == ' ');
        }
        assertTrue("text of " + text.length() + " characters exceeds " + maxLength, text.length() <= maxLength);
    }

    // ===================================================================================
    //                                                                            Settings
    //                                                                            ========
    @Test
    public void test_createDefaultSettings_keepsTheNameIdFormatAndTheAuthnContext() throws Exception {
        final Map<String, String> settings = new SamlAuthenticator().createDefaultSettings();

        assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", settings.get("sp.nameidformat"));
        assertEquals("urn:oasis:names:tc:SAML:2.0:ac:classes:Password", settings.get("security.requested_authncontext"));
        // the key must not carry a duplicated prefix, otherwise the library refuses it
        assertEquals("exact", settings.get("security.requested_authncontextcomparison"));
    }

    @Test
    public void test_createDefaultSettings_areKnownToTheLibrary() throws Exception {
        // the library refuses a key it does not know, so a renamed key would fail every login
        setUpLogin();
        final Map<String, String> properties = createAuthenticator().buildProperties();

        assertNotNull(SamlConfig.fromMap(properties), String.valueOf(properties));
    }

    @Test
    public void test_createDefaultSettings_hasNoBlankValues() throws Exception {
        // the library treats blank values as absent, so a blank default is dead weight
        new SamlAuthenticator().createDefaultSettings().forEach((key, value) -> {
            assertTrue(key + " must not have a blank default", StringUtil.isNotBlank(value));
        });
    }

    @Test
    public void test_createDefaultSettings_omitsSpUrls() throws Exception {
        // SP URLs depend on saml.sp.base.url and are therefore built per request
        final Map<String, String> settings = new SamlAuthenticator().createDefaultSettings();

        assertFalse(settings.containsKey("sp.entityid"));
        assertFalse(settings.containsKey("sp.assertion_consumer_service.url"));
        assertFalse(settings.containsKey("sp.single_logout_service.url"));
    }

    @Test
    public void test_buildProperties_spUrlsUseDefaultBaseUrl() throws Exception {
        final Map<String, String> properties = createAuthenticator().buildProperties();

        assertEquals("http://localhost:8080/sso/metadata", properties.get("sp.entityid"));
        assertEquals("http://localhost:8080/sso/", properties.get("sp.assertion_consumer_service.url"));
    }

    @Test
    public void test_buildProperties_singleLogoutUrlFollowsTheOneOfTheIdp() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticator();
        // there is nothing to send a logout message to
        assertFalse(authenticator.buildProperties().containsKey("sp.single_logout_service.url"));

        ComponentUtil.getSystemProperties().setProperty("saml.idp.single_logout_service.url", TestIdp.SLO);

        assertEquals("http://localhost:8080/sso/logout", authenticator.buildProperties().get("sp.single_logout_service.url"));
    }

    @Test
    public void test_buildProperties_leavesTheKeysOfThePluginOut() throws Exception {
        // the library refuses a key it does not know, and these are read by the authenticator itself
        final DynamicProperties systemProperties = ComponentUtil.getSystemProperties();
        setUpLogin();
        systemProperties.setProperty("saml.request.id.ttl", "600");
        systemProperties.setProperty("saml.attribute.group.name", "groups");
        systemProperties.setProperty("saml.attribute.role.name", "roles");
        systemProperties.setProperty("saml.default.groups", "user");
        systemProperties.setProperty("saml.default.roles", "user");

        final Map<String, String> properties = createAuthenticator().buildProperties();

        assertFalse(String.valueOf(properties),
                properties.keySet().stream().anyMatch(k -> k.startsWith("attribute.") || k.startsWith("default.")));
        assertFalse(String.valueOf(properties), properties.containsKey("request.id.ttl") || properties.containsKey("sp.base.url"));
        assertNotNull(SamlConfig.fromMap(properties), String.valueOf(properties));
    }

    @Test
    public void test_buildProperties_dropsARetiredKeyAndSaysSoOnce() throws Exception {
        // an upgrade must not stop every login over a key that was only ever a permission
        final SamlAuthenticator authenticator = createAuthenticator();
        final DynamicProperties systemProperties = ComponentUtil.getSystemProperties();
        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            setUpLogin();
            systemProperties.setProperty("saml.security.want_xml_validation", "true");
            systemProperties.setProperty("saml.security.reject_missing_audience", "true");

            final Map<String, String> properties = authenticator.buildProperties();
            authenticator.buildProperties();
            authenticator.getServiceProvider();

            assertFalse(String.valueOf(properties), properties.containsKey("security.want_xml_validation"));
            assertFalse(String.valueOf(properties), properties.containsKey("security.reject_missing_audience"));
            assertEquals(1, warnings(appender).size(), String.valueOf(warnings(appender)));
            assertTrue(warnings(appender).get(0), warnings(appender).get(0).contains("saml.security.want_xml_validation"));
            assertTrue(warnings(appender).get(0), warnings(appender).get(0).contains("saml.security.reject_missing_audience"));

            // a different set of retired keys is reported again
            systemProperties.setProperty("saml.idp.certfingerprint", "afe71c28ef740bc87425be13a2263d37971da1f9");
            authenticator.buildProperties();
            assertEquals(2, warnings(appender).size(), String.valueOf(warnings(appender)));
            assertTrue(warnings(appender).get(1), warnings(appender).get(1).contains("saml.idp.certfingerprint"));
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_buildProperties_forTheMetadataAlwaysNamesTheSingleLogoutService() throws Exception {
        // the metadata is what the IdP is registered from, and it is registered before the IdP URL is known
        final SamlAuthenticator authenticator = createAuthenticator();
        setUpBaseUrl();

        assertFalse(authenticator.buildProperties().containsKey("sp.single_logout_service.url"));
        assertEquals(TestIdp.SLS, authenticator.buildProperties(true).get("sp.single_logout_service.url"));
    }

    @Test
    public void test_getServiceProvider_spUrlsUseDefaultBaseUrl() throws Exception {
        setUpIdp();

        final SamlConfig config = createAuthenticator().getServiceProvider().config();

        assertEquals("http://localhost:8080/sso/metadata", config.spEntityId());
        assertEquals("http://localhost:8080/sso/", config.assertionConsumerServiceUrl());
        assertNull(config.singleLogoutServiceUrl(), "single logout is not configured");
    }

    @Test
    public void test_getServiceProvider_spUrlsFollowBaseUrlChangedAfterStartup() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticator();
        setUpIdp();
        ComponentUtil.getSystemProperties().setProperty("saml.idp.single_logout_service.url", TestIdp.SLO);

        // the property is changed after the authenticator was built, as the admin UI does
        setUpBaseUrl();

        final SamlConfig config = authenticator.getServiceProvider().config();
        assertEquals(TestIdp.SP, config.spEntityId());
        assertEquals(TestIdp.ACS, config.assertionConsumerServiceUrl());
        assertEquals(TestIdp.SLS, config.singleLogoutServiceUrl());
    }

    @Test
    public void test_getServiceProvider_blankPropertyKeepsDefault() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticator();
        final DynamicProperties systemProperties = ComponentUtil.getSystemProperties();
        setUpIdp();
        systemProperties.setProperty("saml.sp.entityid", StringUtil.EMPTY);
        systemProperties.setProperty("saml.sp.assertion_consumer_service.url", "  ");

        final SamlConfig config = authenticator.getServiceProvider().config();

        assertEquals("http://localhost:8080/sso/metadata", config.spEntityId());
        assertEquals("http://localhost:8080/sso/", config.assertionConsumerServiceUrl());
    }

    @Test
    public void test_getServiceProvider_blankPropertyFallsBackToLibraryDefault() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticator();
        final DynamicProperties systemProperties = ComponentUtil.getSystemProperties();
        setUpIdp();
        assertEquals("urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
                authenticator.getServiceProvider().config().requestedAuthnContext());

        // clearing the key is the documented way of not constraining the authentication
        // method; falling back to the Fess default instead would keep sending
        // RequestedAuthnContext=Password and break an IdP that enforces MFA
        systemProperties.setProperty("saml.security.requested_authncontext", StringUtil.EMPTY);
        systemProperties.setProperty("saml.sp.nameidformat", "  ");

        final SamlConfig config = authenticator.getServiceProvider().config();
        assertNull(config.requestedAuthnContext(), "a blank value removes the requested context");
        assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", config.nameIdFormat());
    }

    @Test
    public void test_getServiceProvider_cachedUntilPropertiesChange() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticator();
        final DynamicProperties systemProperties = ComponentUtil.getSystemProperties();
        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            setUpIdp();
            final ServiceProvider first = authenticator.getServiceProvider();
            final ServiceProvider second = authenticator.getServiceProvider();

            // rebuilding re-parses the IdP certificate and logs the security warnings again,
            // so unchanged properties must reuse the instance
            assertSame(first, second);
            assertTrue(String.valueOf(warnings(appender)), warnings(appender).isEmpty());

            systemProperties.setProperty("saml.security.want_assertions_signed", "true");
            final ServiceProvider rebuilt = authenticator.getServiceProvider();

            Assertions.assertNotSame(first, rebuilt);
            assertTrue(rebuilt.config().wantAssertionsSigned());
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_getServiceProvider_cacheFollowsBaseUrlChangedAfterStartup() throws Exception {
        // the computed SP URLs are not system properties, so the cache key has to include them
        final SamlAuthenticator authenticator = createAuthenticator();
        setUpIdp();
        assertEquals("http://localhost:8080/sso/metadata", authenticator.getServiceProvider().config().spEntityId());

        setUpBaseUrl();

        assertEquals(TestIdp.SP, authenticator.getServiceProvider().config().spEntityId());
    }

    @Test
    public void test_getServiceProvider_propertyOverridesDefault() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticator();
        final DynamicProperties systemProperties = ComponentUtil.getSystemProperties();
        setUpIdp();
        systemProperties.setProperty("saml.sp.entityid", "https://sp.example.com/metadata");
        systemProperties.setProperty("saml.security.want_assertions_signed", "true");

        final SamlConfig config = authenticator.getServiceProvider().config();

        assertEquals("https://sp.example.com/metadata", config.spEntityId());
        assertTrue(config.wantAssertionsSigned());
    }

    @Test
    public void test_getServiceProvider_refusesAKeyTheLibraryDoesNotKnow() throws Exception {
        // a mistyped security setting must not be ignored
        setUpIdp();
        ComponentUtil.getSystemProperties().setProperty("saml.security.want_assertions_signd", "true");

        final org.codelibs.saml4j.SamlConfigException e =
                Assertions.assertThrows(org.codelibs.saml4j.SamlConfigException.class, () -> createAuthenticator().getServiceProvider());

        assertTrue(e.getMessage(), e.getMessage().contains("security.want_assertions_signd"));
    }

    @Test
    public void test_logSecurityWarnings_reportsUnsignedLogoutMessages() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticator();
        final DynamicProperties systemProperties = ComponentUtil.getSystemProperties();
        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            setUpIdp();
            systemProperties.setProperty("saml.security.want_logout_signed", "false");
            // without a single logout service there is nothing to send a LogoutRequest to
            authenticator.getServiceProvider();
            assertTrue(String.valueOf(warnings(appender)), warnings(appender).isEmpty());

            systemProperties.setProperty("saml.idp.single_logout_service.url", TestIdp.SLO);
            authenticator.getServiceProvider();

            // an unsigned LogoutRequest ends the session of whoever it names
            assertEquals(1, warnings(appender).size(), String.valueOf(warnings(appender)));
            assertTrue(warnings(appender).get(0), warnings(appender).get(0).contains("unsigned_logout_accepted"));

            systemProperties.setProperty("saml.security.want_logout_signed", "true");
            authenticator.getServiceProvider();

            assertEquals(1, warnings(appender).size(), String.valueOf(warnings(appender)));
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_logSecurityWarnings_reportsDeprecatedAlgorithmsAndKeyTransport() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticator();
        final DynamicProperties systemProperties = ComponentUtil.getSystemProperties();
        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            setUpIdp();
            systemProperties.setProperty("saml.security.allow_deprecated_alg", "true");
            authenticator.getServiceProvider();

            assertEquals(1, warnings(appender).size(), String.valueOf(warnings(appender)));
            assertTrue(warnings(appender).get(0), warnings(appender).get(0).contains("deprecated_signature_algorithms_accepted"));
            assertFalse(warnings(appender).get(0), warnings(appender).get(0).contains("rsa_1_5_key_transport_accepted"));

            // RSA 1.5 can only be accepted with a key to decrypt with
            systemProperties.setProperty("saml.sp.privatekey", TestIdp.keyPem("sp"));
            systemProperties.setProperty("saml.security.allow_rsa_1_5", "true");
            authenticator.getServiceProvider();

            assertEquals(2, warnings(appender).size(), String.valueOf(warnings(appender)));
            assertTrue(warnings(appender).get(1), warnings(appender).get(1).contains("deprecated_signature_algorithms_accepted"));
            assertTrue(warnings(appender).get(1), warnings(appender).get(1).contains("rsa_1_5_key_transport_accepted"));
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_getServiceProvider_logsSecurityWarningsUntilTheyChange() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticator();
        final DynamicProperties systemProperties = ComponentUtil.getSystemProperties();
        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            setUpIdp();
            systemProperties.setProperty("saml.security.allow_deprecated_alg", "true");
            authenticator.getServiceProvider();
            authenticator.getServiceProvider();

            // the weakened setting is reported, but only once
            assertEquals(1, warnings(appender).size(), String.valueOf(warnings(appender)));

            // a rebuild for a reason that has nothing to do with it does not repeat it
            systemProperties.setProperty("saml.security.clock_drift", "90");
            authenticator.getServiceProvider();
            assertEquals(1, warnings(appender).size(), String.valueOf(warnings(appender)));

            systemProperties.setProperty("saml.idp.single_logout_service.url", TestIdp.SLO);
            systemProperties.setProperty("saml.security.want_logout_signed", "false");
            authenticator.getServiceProvider();

            // the warnings differ, so they are reported again
            assertEquals(2, warnings(appender).size(), String.valueOf(warnings(appender)));
            assertTrue(warnings(appender).get(1), warnings(appender).get(1).contains("unsigned_logout_accepted"));

            // and once they are gone nothing is logged
            systemProperties.remove("saml.security.allow_deprecated_alg");
            systemProperties.remove("saml.security.want_logout_signed");
            authenticator.getServiceProvider();
            assertEquals(2, warnings(appender).size(), String.valueOf(warnings(appender)));
        } finally {
            appender.detach();
        }
    }

    // ===================================================================================
    //                                                                            Metadata
    //                                                                            ========
    @Test
    public void test_getMetadataResponse_withoutIdpSettings() throws Exception {
        // the SP metadata is what the IdP is registered from, so it must not require saml.idp.*
        final SamlAuthenticator authenticator = createAuthenticator();
        getMockRequest();
        setUpBaseUrl();

        final ActionResponse response = authenticator.getResponse(SsoResponseType.METADATA);

        assertTrue(String.valueOf(response), response instanceof StreamResponse);
        assertEquals("metadata.xml", ((StreamResponse) response).getFileName());
    }

    @Test
    public void test_getMetadataResponse_reportsInvalidSpSettings() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticator();
        getMockRequest();
        // an SP URL that is not a URL
        ComponentUtil.getSystemProperties().setProperty("saml.sp.assertion_consumer_service.url", "not a url");

        final SsoMessageException e =
                Assertions.assertThrows(SsoMessageException.class, () -> authenticator.getResponse(SsoResponseType.METADATA));

        assertNotNull(e.getCause(), "the cause carries the reason");
        assertTrue(e.getCause().getMessage(), e.getCause().getMessage().contains("sp.assertion_consumer_service.url"));
    }

    // ===================================================================================
    //                                                             Assertion Consumer Service
    //                                                             ==========================
    @Test
    public void test_containsSamlResponse() throws Exception {
        final SamlAuthenticator authenticator = new SamlAuthenticator();

        assertFalse(authenticator.containsSamlResponse(getMockRequest()));

        final MockletHttpServletRequest blank = getMockRequest();
        blank.setParameter("SAMLResponse", "  ");
        assertFalse(authenticator.containsSamlResponse(blank));

        final MockletHttpServletRequest posted = getMockRequest();
        posted.setParameter("SAMLResponse", "PHNhbWxwOlJlc3BvbnNlIC8+");
        assertTrue(authenticator.containsSamlResponse(posted));
    }

    @Test
    public void test_getLoginCredential_unmatchedResponseFailsInsteadOfRedirecting() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticator();
        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            setUpLogin();
            // the IdP posts the assertion cross-site, so a SameSite=Lax cookie is not sent back
            // and the session holding the AuthnRequest ID is unreachable
            final MockletHttpServletRequest request = getMockRequest();
            post(request, "PHNhbWxwOlJlc3BvbnNlIC8+");

            // redirecting to the IdP again would come straight back in the same state
            assertNull(authenticator.getLoginCredential());
            assertEquals(1, warnings(appender).size(), String.valueOf(warnings(appender)));
            assertTrue(warnings(appender).get(0), warnings(appender).get(0).contains("no matching AuthnRequest ID"));
            // there is no session at all, which is the one situation the cookie really explains,
            // so this is where that guidance has to stay
            assertTrue(warnings(appender).get(0), warnings(appender).get(0).contains("tomcat.sameSiteCookies"));
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_getLoginCredential_requestWithoutResponseStartsLogin() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        final MockletHttpServletRequest request = getMockRequest();

        final LoginCredential credential = authenticator.getLoginCredential();

        assertTrue(String.valueOf(credential), credential instanceof ActionResponseCredential);
        // the browser is sent to the IdP with a request whose ID is the one that was stored
        final String redirect = String.valueOf(((ActionResponseCredential) credential).execute());
        assertTrue(redirect, redirect.contains(TestIdp.SSO + "?SAMLRequest="));
        final Set<String> pending = pendingRequestIds(request.getSession(false));
        assertEquals(1, pending.size(), String.valueOf(pending));
        final String message = redirectedMessage(redirect.substring(redirect.indexOf(TestIdp.SSO), redirect.indexOf(", AS_IS")));
        assertTrue(message, message.contains("ID=\"" + pending.iterator().next() + "\""));
        assertTrue(message, message.contains(TestIdp.SP));
    }

    @Test
    public void test_getLoginCredential_reportsAnInvalidIdpConfigurationAsARejectedRequest() throws Exception {
        // Every anonymous GET /sso/ reaches the AuthnRequest of an unconfigured server, and
        // SsoAction logs an SsoStateException as one line where it logs anything else with a stack
        // trace. It does not log the cause, so the setting the library names has to be in the message.
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        getMockRequest();

        final SsoStateException e = Assertions.assertThrows(SsoStateException.class, authenticator::getLoginCredential);

        assertTrue(e.getMessage(), e.getMessage().contains("idp.entityid"));
        assertFalse(e.getMessage(), e.getMessage().matches("(?s).*[\\r\\n].*"));
    }

    @Test
    public void test_getLoginCredential_namesTheKeyTheLibraryDoesNotKnow() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        ComponentUtil.getSystemProperties().setProperty("saml.security.want_assertions_signd", "true");
        getMockRequest();

        final SsoStateException e = Assertions.assertThrows(SsoStateException.class, authenticator::getLoginCredential);

        assertTrue(e.getMessage(), e.getMessage().contains("security.want_assertions_signd"));
    }

    @Test
    public void test_getLoginCredential_keepsTheStackTraceOfAnUnexpectedFailureToStartALogin() throws Exception {
        // Only the configuration is the operator's mistake to read off one line. Anything else
        // that stops the AuthnRequest is a fault of this server.
        final SamlAuthenticator authenticator = new SamlAuthenticator() {
            @Override
            protected ServiceProvider getServiceProvider() {
                throw new IllegalStateException("the service provider could not be built");
            }
        };
        getMockRequest();

        final SsoLoginException e = Assertions.assertThrows(SsoLoginException.class, authenticator::getLoginCredential);

        assertFalse(e.toString(), e instanceof SsoStateException);
    }

    @Test
    public void test_getLoginCredential_requestWithoutResponseKeepsPendingRequestIds() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        // FessSearchAction redirects every unauthenticated page hit to /sso/, so a session
        // that expires with two tabs open sends two AuthnRequests. A single slot made the
        // second visit abandon the first login, and the first assertion back then consumed
        // the slot, failed the InResponseTo comparison and took both tabs down with it.
        final MockletHttpServletRequest request = getMockRequest();

        authenticator.getLoginCredential();
        final Set<String> afterFirstVisit = pendingRequestIds(request.getSession(false));
        clock.addAndGet(1000L);
        authenticator.getLoginCredential();
        final Set<String> afterSecondVisit = pendingRequestIds(request.getSession(false));

        assertEquals(1, afterFirstVisit.size(), String.valueOf(afterFirstVisit));
        assertEquals(2, afterSecondVisit.size(), String.valueOf(afterSecondVisit));
        assertTrue(String.valueOf(afterSecondVisit), afterSecondVisit.containsAll(afterFirstVisit));
        // an XML ID cannot start with a digit
        afterSecondVisit.forEach(requestId -> assertTrue(requestId, requestId.startsWith("_")));
    }

    @Test
    public void test_getLoginCredential_requestWithoutResponseCarriesOverALegacyRequestId() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        // A session created before the map held a bare String there. Casting it to the map would
        // end the login with a ClassCastException, and dropping it would abandon a login that was
        // already in flight over the upgrade.
        final MockletHttpServletRequest request = getMockRequest();
        request.getSession().setAttribute(SAML_STATE, "_legacy");

        final LoginCredential credential = authenticator.getLoginCredential();

        assertTrue(String.valueOf(credential), credential instanceof ActionResponseCredential);
        final Set<String> pending = pendingRequestIds(request.getSession(false));
        assertEquals(2, pending.size(), String.valueOf(pending));
        assertTrue(String.valueOf(pending), pending.contains("_legacy"));
    }

    @Test
    public void test_getRequestIdMap_replacesAnUnusableSessionValue() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        final HttpSession session = getMockRequest().getSession();
        session.setAttribute(SAML_STATE, Integer.valueOf(42));

        final Map<String, Long> requestIdMap = authenticator.getRequestIdMap(session);

        // Anything that is not a live map and not a legacy ID is discarded rather than cast.
        assertTrue(requestIdMap.toString(), requestIdMap.isEmpty());
        assertTrue(String.valueOf(requestIdMap), requestIdMap instanceof ConcurrentHashMap);
        // The map that was handed out is the one stored back, so later writes are not lost.
        assertSame(requestIdMap, session.getAttribute(SAML_STATE));
    }

    @Test
    public void test_getLoginCredential_capsThePendingRequestIds() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        // /sso/ is anonymous and answers GET, so a page embedding it as a sub-resource would
        // otherwise grow the session attribute for as long as the session lives.
        final MockletHttpServletRequest request = getMockRequest();
        final List<String> issuedRequestIds = new ArrayList<>();
        for (int i = 0; i < 12; i++) {
            clock.addAndGet(1000L);
            authenticator.getLoginCredential();
            pendingRequestIds(request.getSession(false)).stream()
                    .filter(requestId -> !issuedRequestIds.contains(requestId))
                    .forEach(issuedRequestIds::add);
        }

        final Set<String> pending = pendingRequestIds(request.getSession(false));

        assertEquals(12, issuedRequestIds.size(), String.valueOf(issuedRequestIds));
        assertEquals(10, pending.size(), String.valueOf(pending));
        // The two oldest were evicted; the most recent are the ones a user can still finish.
        assertFalse(String.valueOf(pending), pending.contains(issuedRequestIds.get(0)));
        assertFalse(String.valueOf(pending), pending.contains(issuedRequestIds.get(1)));
        assertTrue(String.valueOf(pending), pending.contains(issuedRequestIds.get(2)));
        assertTrue(String.valueOf(pending), pending.contains(issuedRequestIds.get(11)));
    }

    @Test
    public void test_getLoginCredential_expiredRequestIdCannotBeAnswered() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        final MockletHttpServletRequest request = getMockRequest();
        final String requestId = startLogin(authenticator, request);

        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            // getRequestIdTtl() defaults to 3600 and is compared in seconds
            clock.addAndGet(3601L * 1000L);
            post(request, signedResponse(requestId, null));

            // a response that would have logged the user in is refused all the same
            assertNull(authenticator.getLoginCredential());
            assertEquals(1, warnings(appender).size(), String.valueOf(warnings(appender)));
            // The session was found and it did hold the ID until this very request pruned it,
            // so the cookie demonstrably arrived. Reporting this as the SameSite case sends an
            // operator whose cookie settings are already right off to change them, and this is
            // the ordinary outcome of a user who walks away mid-login.
            assertTrue(warnings(appender).get(0), warnings(appender).get(0).contains("had expired"));
            assertTrue(warnings(appender).get(0), warnings(appender).get(0).contains("all 1 pending"));
            assertTrue(warnings(appender).get(0), warnings(appender).get(0).contains("saml.request.id.ttl"));
            assertFalse(warnings(appender).get(0), warnings(appender).get(0).contains("tomcat.sameSiteCookies"));
            assertTrue(pendingRequestIds(request.getSession(false)).toString(), pendingRequestIds(request.getSession(false)).isEmpty());
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_getLoginCredential_responseMatchingNoPendingRequestIdFails() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        final MockletHttpServletRequest request = getMockRequest();
        startLogin(authenticator, request);
        final Set<String> pending = pendingRequestIds(request.getSession(false));

        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            post(request, signedResponse("_never_sent", null));

            // Answering it with a fresh AuthnRequest would bounce off an IdP that is already
            // authenticated and come straight back here, forever.
            assertNull(authenticator.getLoginCredential());
            assertEquals(1, warnings(appender).size(), String.valueOf(warnings(appender)));
            assertTrue(warnings(appender).get(0), warnings(appender).get(0).contains("no matching AuthnRequest ID"));
            assertTrue(warnings(appender).get(0), warnings(appender).get(0).contains("(1 pending)"));
            // a refusal that says what to look at, and no stack trace for a request anyone can send
            appender.eventsAt(Level.WARN).forEach(e -> assertNull(e.getThrown(), String.valueOf(e.getThrown())));
            // A response nobody asked for must not be able to burn a login that is in flight:
            // the assertion consumer service is reachable cross-site, since SAML needs
            // SameSite=none, so consuming an ID here would be a denial of service per request.
            Assertions.assertEquals(pending, pendingRequestIds(request.getSession(false)));
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_getLoginCredential_reportsWhyTheResponseWasRefused() throws Exception {
        // The reason is a category: it covers a bad signature, an expired assertion, a foreign
        // audience and a rewritten destination alike. On its own it tells an administrator only
        // that the login failed, so the detail has to reach the log too, at the level a shipped
        // configuration logs at.
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        final MockletHttpServletRequest request = getMockRequest();
        final String requestId = startLogin(authenticator, request);

        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            // signed by a key the IdP certificate does not belong to
            post(request, signedResponse(requestId, spec -> spec.signKey = TestIdp.OTHER_KEY));
            assertNull(authenticator.getLoginCredential());

            assertEquals(1, warnings(appender).size(), String.valueOf(warnings(appender)));
            final String failure = warnings(appender).get(0);
            final String prefix = "Authentication failed: INVALID_SIGNATURE - ";
            assertTrue(failure, failure.startsWith(prefix));
            assertTrue(failure, failure.length() > prefix.length());
            appender.eventsAt(Level.WARN).forEach(e -> assertNull(e.getThrown(), String.valueOf(e.getThrown())));
            // the refusal does not consume the ID: the login is still live
            assertTrue(pendingRequestIds(request.getSession(false)).contains(requestId));
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_getLoginCredential_sanitizesTheStatusCodeTheSenderPutInTheLog() throws Exception {
        // the library copies the StatusCode of a non-success response into the detail of the
        // refusal as it is written, and checks it before the signature, so an anonymous POST
        // reaches this line with whatever the sender typed there.
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        final MockletHttpServletRequest request = getMockRequest();
        final String requestId = startLogin(authenticator, request);
        post(request, signedResponse(requestId, spec -> spec.status = FORGED_STATUS_CODE));

        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            assertNull(authenticator.getLoginCredential());

            assertEquals(1, warnings(appender).size(), String.valueOf(warnings(appender)));
            final String failure = warnings(appender).get(0);
            assertTrue(failure, failure.startsWith("Authentication failed: STATUS_NOT_SUCCESS - "));
            assertTrue(failure, failure.contains("WARN forged line"));
            assertSafeForLog(failure,
                    "Authentication failed: STATUS_NOT_SUCCESS - ".length() + SamlAuthenticator.MAX_LOGGED_FAILURE_REASON_LENGTH + 3);
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_getLoginCredential_answersTheOlderOfTwoPendingRequestIds() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        final MockletHttpServletRequest request = getMockRequest();
        final String olderRequestId = startLogin(authenticator, request);
        clock.addAndGet(1000L);
        final String newerRequestId = startLogin(authenticator, request);

        // the first tab's assertion comes back while the second tab's AuthnRequest is the
        // most recent one, which is the case that used to fail both logins
        post(request, signedResponse(olderRequestId, null));
        final LoginCredential credential = authenticator.getLoginCredential();

        assertTrue(String.valueOf(credential), credential instanceof SamlCredential);
        Assertions.assertEquals(Set.of(newerRequestId), pendingRequestIds(request.getSession(false)));
    }

    /**
     * Seeds a session with one pending AuthnRequest ID and puts {@code samlResponse} on the request, which is
     * the state a malformed callback arrives in.
     */
    private MockletHttpServletRequest postRawSamlResponse(final SamlAuthenticator authenticator, final String samlResponse) {
        final MockletHttpServletRequest request = getMockRequest();
        authenticator.getLoginCredential();
        post(request, samlResponse);
        return request;
    }

    @Test
    public void test_getLoginCredential_unparsableResponseIsWarnedWithoutAStackTrace() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        final MockletHttpServletRequest request = postRawSamlResponse(authenticator, NOT_BASE64);

        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            assertNull(authenticator.getLoginCredential());

            // /sso/ is anonymous, so this is a rejected request rather than a fault of this
            // server: one line, and no stack trace an unauthenticated client can repeat.
            final List<LogEvent> warnEvents = appender.eventsAt(Level.WARN);
            assertEquals(1, warnEvents.size(), String.valueOf(warnings(appender)));
            assertTrue(warnings(appender).get(0), warnings(appender).get(0).startsWith("Authentication failed: MALFORMED - "));
            assertNull(warnEvents.get(0).getThrown(), String.valueOf(warnEvents.get(0).getThrown()));
            // the pending ID is not consumed by the failure, which is what makes the same
            // request repeatable for the whole TTL and therefore worth not tracing
            assertEquals(1, pendingRequestIds(request.getSession(false)).size());
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_getLoginCredential_brokenXmlResponseIsWarnedWithoutAStackTrace() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        // base64 that decodes fine and is then not XML reaches the same refusal by a different
        // route, so neither a stricter decoder nor a stricter parser alone closes this
        postRawSamlResponse(authenticator, BROKEN_XML);

        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            assertNull(authenticator.getLoginCredential());

            final List<LogEvent> warnEvents = appender.eventsAt(Level.WARN);
            assertEquals(1, warnEvents.size(), String.valueOf(warnings(appender)));
            assertTrue(warnings(appender).get(0), warnings(appender).get(0).startsWith("Authentication failed: MALFORMED - "));
            assertNull(warnEvents.get(0).getThrown(), String.valueOf(warnEvents.get(0).getThrown()));
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_getLoginCredential_unparsableResponseCanBeRepeatedWithThePendingRequestId() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        final MockletHttpServletRequest request = postRawSamlResponse(authenticator, NOT_BASE64);
        final Set<String> pending = pendingRequestIds(request.getSession(false));
        assertEquals(1, pending.size(), String.valueOf(pending));

        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            assertNull(authenticator.getLoginCredential());
            assertNull(authenticator.getLoginCredential());
            assertNull(authenticator.getLoginCredential());

            // this is the whole reason the trace has to go: the failure leaves the pending ID
            // in place, so the very same anonymous request answers again and again
            assertEquals(3, warnings(appender).size(), String.valueOf(warnings(appender)));
            Assertions.assertEquals(pending, pendingRequestIds(request.getSession(false)));
            appender.eventsAt(Level.WARN).forEach(e -> assertNull(e.getThrown(), e.getMessage().getFormattedMessage()));
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_getLoginCredential_invalidSettingsAreReportedWithoutAStackTrace() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        final MockletHttpServletRequest request = getMockRequest();
        final String requestId = startLogin(authenticator, request);
        // the settings no longer build when the response arrives
        ComponentUtil.getSystemProperties().remove("saml.idp.entityid");
        post(request, signedResponse(requestId, null));

        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            assertNull(authenticator.getLoginCredential());

            final List<LogEvent> warnEvents = appender.eventsAt(Level.WARN);
            assertEquals(1, warnEvents.size(), String.valueOf(warnings(appender)));
            assertTrue(warnings(appender).get(0), warnings(appender).get(0).startsWith("Authentication failed: invalid SAML settings: "));
            assertTrue(warnings(appender).get(0), warnings(appender).get(0).contains("idp.entityid"));
            assertNull(warnEvents.get(0).getThrown(), String.valueOf(warnEvents.get(0).getThrown()));
            assertTrue(pendingRequestIds(request.getSession(false)).contains(requestId));
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_getLoginCredential_nonSamlFailureKeepsItsStackTrace() throws Exception {
        // anything that is not a refusal of the message is a bug in this server rather than a
        // payload an anonymous client chose, so it keeps the trace it always had
        final RuntimeException failure = new IllegalStateException("something this server got wrong");
        final SamlAuthenticator authenticator = new SamlAuthenticator() {
            @Override
            protected LoginCredential processSamlResponse(final HttpServletRequest request, final Map<String, Long> requestIdMap) {
                throw failure;
            }
        };
        registerSystemHelper();
        final MockletHttpServletRequest request = getMockRequest();
        request.getSession().setAttribute(SAML_STATE, new ConcurrentHashMap<>(Map.of("_pending", clock.get())));
        post(request, BROKEN_XML);

        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            assertNull(authenticator.getLoginCredential());

            final List<LogEvent> warnEvents = appender.eventsAt(Level.WARN);
            assertEquals(1, warnEvents.size(), String.valueOf(warnings(appender)));
            assertEquals("Authentication failed.", warnings(appender).get(0));
            assertSame(failure, warnEvents.get(0).getThrown());
        } finally {
            appender.detach();
        }
    }

    // ===================================================================================
    //                                                                    Pending Request IDs
    //                                                                    ===================
    @Test
    public void test_getRequestIdTtl_defaultsToOneHourInSeconds() throws Exception {
        // removeExpiredRequestIds compares (now - created) / 1000 against this value
        assertEquals(3600L, new SamlAuthenticator().getRequestIdTtl());
    }

    @Test
    public void test_getRequestIdTtl_fallsBackWhenTheConfiguredValueIsNotANumber() throws Exception {
        // A typo in conf/system.properties must not fail every login with a
        // NumberFormatException nobody can act on.
        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        ComponentUtil.getFessConfig().setSystemProperty("saml.request.id.ttl", "one hour");
        try {
            assertEquals(3600L, new SamlAuthenticator().getRequestIdTtl());
            assertEquals(1, warnings(appender).size(), String.valueOf(warnings(appender)));
            assertTrue(warnings(appender).get(0), warnings(appender).get(0).contains("saml.request.id.ttl"));
        } finally {
            ComponentUtil.getFessConfig().setSystemProperty("saml.request.id.ttl", "");
            appender.detach();
        }
    }

    @Test
    public void test_getRequestIdTtl_blankValueIsNotReportedAsInvalid() throws Exception {
        // A blank property means "unset" everywhere else in this class, so it must not warn.
        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        ComponentUtil.getFessConfig().setSystemProperty("saml.request.id.ttl", " ");
        try {
            assertEquals(3600L, new SamlAuthenticator().getRequestIdTtl());
            assertTrue(String.valueOf(warnings(appender)), warnings(appender).isEmpty());
        } finally {
            ComponentUtil.getFessConfig().setSystemProperty("saml.request.id.ttl", "");
            appender.detach();
        }
    }

    @Test
    public void test_getRequestIdTtl_fallsBackWhenTheConfiguredValueIsNotPositive() throws Exception {
        // Both values parse, so nothing fails here, but removeExpiredRequestIds compares
        // (now - created) / 1000 against the result: 0 drops the AuthnRequest ID one second after
        // the IdP was sent to, and -1 drops it at once, so every SAML login in the deployment
        // fails. 0 is not a far-fetched thing to write, either: it reads as "no expiry".
        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            ComponentUtil.getFessConfig().setSystemProperty("saml.request.id.ttl", "0");
            assertEquals(3600L, new SamlAuthenticator().getRequestIdTtl());

            ComponentUtil.getFessConfig().setSystemProperty("saml.request.id.ttl", "-1");
            assertEquals(3600L, new SamlAuthenticator().getRequestIdTtl());

            assertEquals(2, warnings(appender).size(), String.valueOf(warnings(appender)));
            assertTrue(warnings(appender).get(0), warnings(appender).get(0).contains("saml.request.id.ttl"));
            // the value that was configured, not only the default that replaced it
            assertTrue(warnings(appender).get(0), warnings(appender).get(0).contains(": 0."));
            assertTrue(warnings(appender).get(1), warnings(appender).get(1).contains(": -1."));
        } finally {
            ComponentUtil.getFessConfig().setSystemProperty("saml.request.id.ttl", "");
            appender.detach();
        }
    }

    @Test
    public void test_getRequestIdTtl_reportsANonPositiveValueDifferentlyFromANonNumericOne() throws Exception {
        // The two mistakes need different corrections, and 0 is a number, so reporting it as
        // invalid would send an administrator hunting for a typo that is not there.
        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            ComponentUtil.getFessConfig().setSystemProperty("saml.request.id.ttl", "0");
            new SamlAuthenticator().getRequestIdTtl();

            ComponentUtil.getFessConfig().setSystemProperty("saml.request.id.ttl", "one hour");
            new SamlAuthenticator().getRequestIdTtl();

            assertEquals(2, warnings(appender).size(), String.valueOf(warnings(appender)));
            final String nonPositive = warnings(appender).get(0);
            final String nonNumeric = warnings(appender).get(1);
            assertTrue(nonPositive, nonPositive.contains("positive"));
            assertFalse(nonPositive, nonPositive.contains("Invalid"));
            assertTrue(nonNumeric, nonNumeric.contains("Invalid"));
            assertFalse(nonNumeric, nonNumeric.contains("positive"));
        } finally {
            ComponentUtil.getFessConfig().setSystemProperty("saml.request.id.ttl", "");
            appender.detach();
        }
    }

    @Test
    public void test_setMaxRequestIds_honoursAPositiveValue() throws Exception {
        // fess_sso++.xml offers 10 as the line to uncomment, so that is what an untouched
        // deployment has to be running with.
        final SamlAuthenticator authenticator = new SamlAuthenticator();
        assertEquals(10, authenticator.maxRequestIds);

        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            authenticator.setMaxRequestIds(1);
            assertEquals(1, authenticator.maxRequestIds);

            authenticator.setMaxRequestIds(50);
            assertEquals(50, authenticator.maxRequestIds);

            assertTrue(String.valueOf(warnings(appender)), warnings(appender).isEmpty());
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_setMaxRequestIds_fallsBackWhenTheValueIsNotPositive() throws Exception {
        // Both values are applied without failing here, but getCandidateRequestIds hands the cap
        // to limit(): 0 leaves processSamlResponse no candidate to try and -1 makes limit() throw,
        // so either way every SAML login in the deployment fails. 0 is not a far-fetched thing to
        // write, either: it reads as "no limit".
        final SamlAuthenticator authenticator = new SamlAuthenticator();
        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            authenticator.setMaxRequestIds(0);
            assertEquals(10, authenticator.maxRequestIds);

            authenticator.setMaxRequestIds(-1);
            assertEquals(10, authenticator.maxRequestIds);

            assertEquals(2, warnings(appender).size(), String.valueOf(warnings(appender)));
            assertTrue(warnings(appender).get(0), warnings(appender).get(0).contains("maxRequestIds"));
            // the value that was configured, not only the default that replaced it
            assertTrue(warnings(appender).get(0), warnings(appender).get(0).contains(": 0."));
            assertTrue(warnings(appender).get(1), warnings(appender).get(1).contains(": -1."));
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_getCandidateRequestIds_isNotEmptiedByANonPositiveCap() throws Exception {
        // The end the guard protects. Taken literally, the cap discards the pending ID the
        // session does hold before processSamlResponse ever sees it, and the login is then
        // reported as a session cookie that never arrived.
        final Map<String, Long> requestIdMap = new ConcurrentHashMap<>();
        requestIdMap.put("_pending", 1000L);
        final SamlAuthenticator authenticator = new SamlAuthenticator();
        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            authenticator.setMaxRequestIds(0);
            Assertions.assertEquals(List.of("_pending"), authenticator.getCandidateRequestIds(requestIdMap));

            // -1 does not merely return nothing: limit() throws, and the caller logs that as
            // "Authentication failed." with no hint of the cap.
            authenticator.setMaxRequestIds(-1);
            Assertions.assertEquals(List.of("_pending"), authenticator.getCandidateRequestIds(requestIdMap));
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_getCandidateRequestIds_offersTheNewestFirstAndNoMoreThanTheCap() throws Exception {
        final Map<String, Long> requestIdMap = new ConcurrentHashMap<>();
        requestIdMap.put("_oldest", 1000L);
        requestIdMap.put("_middle", 2000L);
        requestIdMap.put("_newest", 3000L);
        final SamlAuthenticator authenticator = new SamlAuthenticator();

        Assertions.assertEquals(List.of("_newest", "_middle", "_oldest"), authenticator.getCandidateRequestIds(requestIdMap));

        // lowering the cap at runtime takes effect on the very next response
        authenticator.setMaxRequestIds(2);
        Assertions.assertEquals(List.of("_newest", "_middle"), authenticator.getCandidateRequestIds(requestIdMap));
    }

    @Test
    public void test_getLoginCredential_nonPositiveRequestIdTtlStillAnswersAResponse() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        // Taken literally, this expires the AuthnRequest ID one second after the browser was
        // sent to the IdP, which no round trip can beat: the deployment would answer every
        // login attempt with a warning and no session would ever be created.
        ComponentUtil.getFessConfig().setSystemProperty("saml.request.id.ttl", "0");
        final MockletHttpServletRequest request = getMockRequest();
        final String requestId = startLogin(authenticator, request);

        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            clock.addAndGet(1000L);
            post(request, signedResponse(requestId, null));

            final LoginCredential credential = authenticator.getLoginCredential();

            // it was compared with the pending ID, which was not pruned, and the login went through
            assertTrue(String.valueOf(credential), credential instanceof SamlCredential);
            assertTrue(String.valueOf(warnings(appender)), warnings(appender).stream().noneMatch(w -> w.contains("had expired")));
            assertTrue(String.valueOf(warnings(appender)),
                    warnings(appender).stream().noneMatch(w -> w.contains("no matching AuthnRequest ID")));
            assertFalse(String.valueOf(pendingRequestIds(request.getSession(false))),
                    pendingRequestIds(request.getSession(false)).contains(requestId));
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_logUnmatchedSamlResponse_separatesAnExpiredLoginFromAMissingSessionCookie() throws Exception {
        // Both situations reach the log with nothing pending, so the text is the only thing that
        // can tell them apart, and only one of them is a misconfiguration.
        final SamlAuthenticator authenticator = new SamlAuthenticator();
        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            authenticator.logUnmatchedSamlResponse(0);
            authenticator.logUnmatchedSamlResponseAfterExpiry(1);

            assertEquals(2, warnings(appender).size(), String.valueOf(warnings(appender)));
            final String missingCookie = warnings(appender).get(0);
            final String expired = warnings(appender).get(1);
            assertTrue(missingCookie, missingCookie.contains("tomcat.sameSiteCookies"));
            assertFalse(missingCookie, missingCookie.contains("saml.request.id.ttl"));
            assertTrue(expired, expired.contains("saml.request.id.ttl"));
            assertFalse(expired, expired.contains("tomcat.sameSiteCookies"));
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_hasExpiredSession_needsASessionIdThatIsNoLongerValid() throws Exception {
        final SamlAuthenticator authenticator = new SamlAuthenticator();
        // one request, walked through the three states, because getMockRequest() hands out the
        // same instance for the whole test method
        final MockletHttpServletRequest request = getMockRequest();

        // a browser that is not sending the cookie sends no session id, so nothing was lost
        assertNull(request.getRequestedSessionId());
        assertFalse(authenticator.hasExpiredSession(request));

        // an id that came back with nothing behind it is the case worth naming
        request.addCookie(new Cookie("jsessionid", "AB1C2D3E4F5061728394A5B6C7D8E9F0"));
        assertNotNull(request.getRequestedSessionId());
        assertFalse(request.isRequestedSessionIdValid());
        assertTrue(authenticator.hasExpiredSession(request));

        // an id the container still knows is a live session, not an expired one
        request.getSession();
        assertTrue(request.isRequestedSessionIdValid());
        assertFalse(authenticator.hasExpiredSession(request));
    }

    @Test
    public void test_getLoginCredential_responseWithoutASessionIdBlamesTheCookie() throws Exception {
        // Nothing came back at all, which really is what a SameSite=Lax cookie on a cross-site
        // POST looks like, so this is the one case that keeps that guidance.
        final SamlAuthenticator authenticator = createAuthenticator();
        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            setUpLogin();
            final MockletHttpServletRequest request = getMockRequest();
            post(request, "PHNhbWxwOlJlc3BvbnNlIC8+");
            assertNull(request.getRequestedSessionId());

            assertNull(authenticator.getLoginCredential());
            assertEquals(1, warnings(appender).size(), String.valueOf(warnings(appender)));
            final String warning = warnings(appender).get(0);
            assertTrue(warning, warning.contains("tomcat.sameSiteCookies"));
            assertFalse(warning, warning.contains("session it belongs to had expired"));
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_getLoginCredential_expiredSessionIsNotReportedAsABlockedCookie() throws Exception {
        // The realistic "walked away at the IdP" case arrives exactly like this, because the
        // container reaps the session (30 minutes by default) long before saml.request.id.ttl
        // (3600 seconds) can prune an ID, so the AuthnRequest IDs go with it and the branch that
        // counts pruned IDs is never reached. Reported as the SameSite case it sends an operator
        // whose cookie settings are already right off to change them.
        final SamlAuthenticator authenticator = createAuthenticator();
        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            setUpLogin();
            final MockletHttpServletRequest request = getMockRequest();
            post(request, "PHNhbWxwOlJlc3BvbnNlIC8+");
            request.addCookie(new Cookie("jsessionid", "AB1C2D3E4F5061728394A5B6C7D8E9F0"));
            // the cookie demonstrably arrived; there is simply no session behind it any more
            assertNotNull(request.getRequestedSessionId());
            assertNull(request.getSession(false));

            // still refused: bouncing back to an IdP that is already authenticated would only
            // post the same unmatched assertion straight back
            assertNull(authenticator.getLoginCredential());
            assertEquals(1, warnings(appender).size(), String.valueOf(warnings(appender)));
            final String warning = warnings(appender).get(0);
            assertTrue(warning, warning.contains("session it belongs to had expired"));
            assertFalse(warning, warning.contains("tomcat.sameSiteCookies"));
            // raising the TTL cannot extend a session that is already the shorter of the two
            assertTrue(warning, warning.contains("raising that value does not help"));
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_getLoginCredential_prunedRequestIdsStillNameTheTtl() throws Exception {
        // The third case: the session is alive and its cookie is valid, and only the IDs it held
        // ran out of time. That one really is about saml.request.id.ttl, so the session-expiry
        // wording must not take it over.
        final SamlAuthenticator authenticator = createAuthenticatorWithControlledClock();
        setUpLogin();
        final MockletHttpServletRequest request = getMockRequest();
        request.addCookie(new Cookie("jsessionid", "AB1C2D3E4F5061728394A5B6C7D8E9F0"));
        final String requestId = startLogin(authenticator, request);
        assertTrue(request.isRequestedSessionIdValid());

        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            clock.addAndGet(3601L * 1000L);
            post(request, signedResponse(requestId, null));

            assertNull(authenticator.getLoginCredential());
            assertEquals(1, warnings(appender).size(), String.valueOf(warnings(appender)));
            final String warning = warnings(appender).get(0);
            assertTrue(warning, warning.contains("all 1 pending AuthnRequest ID(s) of the session had expired"));
            assertFalse(warning, warning.contains("session it belongs to had expired"));
            assertFalse(warning, warning.contains("tomcat.sameSiteCookies"));
        } finally {
            appender.detach();
        }
    }

    // ===================================================================================
    //                                                                Single Logout Service
    //                                                                =====================
    @Test
    public void test_getLogoutResponse_withoutIdpSingleLogoutServiceUrl() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticator();
        setUpLogin();
        // a real logout message, so that the missing configuration is what fails
        final MockletHttpServletRequest request = getMockRequest();
        sendLogoutRequest(request, "_logout1", USER, true);

        final SsoMessageException e =
                Assertions.assertThrows(SsoMessageException.class, () -> authenticator.getResponse(SsoResponseType.LOGOUT));

        assertNotNull(e.getCause());
        assertTrue(e.getCause().getMessage(), e.getCause().getMessage().contains("single logout service URL"));
    }

    @Test
    public void test_getLogoutResponse_withoutSamlLogoutMessageAndWithoutSlo() throws Exception {
        // single logout is optional, so the anonymous visit below reaches a deployment that never
        // configured it. It must still be rejected as a request rather than reported as a fault,
        // or /sso/logout writes a stack trace per anonymous hit on every such deployment.
        final SamlAuthenticator authenticator = createAuthenticator();
        getMockRequest();

        final SsoMessageException e =
                Assertions.assertThrows(SsoMessageException.class, () -> authenticator.getResponse(SsoResponseType.LOGOUT));

        assertTrue(String.valueOf(e.getCause()), e.getCause() instanceof SsoStateException);
        assertEquals("The request carries no SAML logout message.", e.getCause().getMessage());
    }

    @Test
    public void test_getLogoutResponse_withoutSamlLogoutMessage() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticator();
        setUpSlo();
        // /sso/logout is anonymous, so it also receives plain visits carrying no SAML message
        getMockRequest();

        final SsoMessageException e =
                Assertions.assertThrows(SsoMessageException.class, () -> authenticator.getResponse(SsoResponseType.LOGOUT));

        // a rejected request, not a fault: the cause decides that SsoAction logs it without a stack trace
        assertTrue(String.valueOf(e.getCause()), e.getCause() instanceof SsoStateException);
        assertEquals("The request carries no SAML logout message.", e.getCause().getMessage());
    }

    @Test
    public void test_getLogoutResponse_rejectsAnUnusableLogoutMessageWithoutAStackTrace() throws Exception {
        // The message here is one the sender supplied and the library refused. /sso/logout is
        // anonymous and, because SAML requires SameSite=none, reachable cross-site, so an
        // unauthenticated client can repeat this at will; a stack trace per attempt would let it
        // fill the log. The cause is what SsoAction branches on to log the message alone.
        final SamlAuthenticator authenticator = createAuthenticator();
        setUpSlo();
        final MockletHttpServletRequest request = getMockRequest();
        // a LogoutRequest nobody signed, and one that is no message at all
        sendLogoutRequest(request, "_unsigned", USER, false);

        final SsoMessageException unsigned =
                Assertions.assertThrows(SsoMessageException.class, () -> authenticator.getResponse(SsoResponseType.LOGOUT));

        assertTrue(String.valueOf(unsigned.getCause()), unsigned.getCause() instanceof SsoStateException);
        assertTrue(unsigned.getCause().getMessage(), unsigned.getCause().getMessage().startsWith("NOT_SIGNED: "));

        request.setParameter("SAMLRequest", "................");
        request.setQueryString("SAMLRequest=................");
        final SsoMessageException garbage =
                Assertions.assertThrows(SsoMessageException.class, () -> authenticator.getResponse(SsoResponseType.LOGOUT));

        assertTrue(String.valueOf(garbage.getCause()), garbage.getCause() instanceof SsoStateException);
    }

    @Test
    public void test_getLogoutResponse_showsOnlyTheReasonCodeOfARejectedLogoutMessage() throws Exception {
        // The detail of a refused message quotes what the sender wrote (here the SigAlg of a redirect). It goes to the log;
        // the login page that the anonymous caller is sent to must show the reason code and nothing the caller chose.
        final SamlAuthenticator authenticator = createAuthenticator();
        setUpSlo();
        final MockletHttpServletRequest request = getMockRequest();
        final String text = "Your session expired. Call IT and give your password";
        request.setMethod("GET");
        request.setParameter("SAMLRequest", "eA==");
        request.setParameter("SigAlg", text);
        request.setParameter("Signature", "AAAA");
        request.setQueryString("SAMLRequest=eA%3D%3D&SigAlg=" + text.replace(" ", "%20") + "&Signature=AAAA");

        final SsoMessageException e =
                Assertions.assertThrows(SsoMessageException.class, () -> authenticator.getResponse(SsoResponseType.LOGOUT));

        assertTrue(e.getCause().getMessage(), e.getCause().getMessage().contains(text));
        final FessMessages messages = new FessMessages();
        e.getMessageCode().message(messages);
        final Object[] values = messages.accessByFlatIterator().next().getValues();
        assertEquals(1, values.length);
        assertEquals("INVALID_SIGNATURE", values[0]);
    }

    @Test
    public void test_getLogoutResponse_withInvalidSettingsIsOneLineAndNamesNoSetting() throws Exception {
        // /sso/logout is anonymous: while the settings are invalid every request would write a stack trace, and the
        // login page it is sent to must not tell the caller which setting is wrong.
        final SamlAuthenticator authenticator = createAuthenticator();
        setUpSlo();
        ComponentUtil.getSystemProperties().setProperty("saml.security.want_assertions_signd", "true");
        final MockletHttpServletRequest request = getMockRequest();
        request.setMethod("GET");
        request.setParameter("SAMLRequest", "eA==");
        request.setQueryString("SAMLRequest=eA%3D%3D");

        final SsoMessageException e =
                Assertions.assertThrows(SsoMessageException.class, () -> authenticator.getResponse(SsoResponseType.LOGOUT));

        assertTrue(String.valueOf(e.getCause()), e.getCause() instanceof SsoStateException);
        assertTrue(e.getCause().getMessage(), e.getCause().getMessage().contains("want_assertions_signd"));
        final FessMessages messages = new FessMessages();
        e.getMessageCode().message(messages);
        assertEquals("The SAML settings are invalid.", messages.accessByFlatIterator().next().getValues()[0]);
    }

    @Test
    public void test_getLogoutResponse_sanitizesTheStatusCodeOfALogoutResponse() throws Exception {
        // The message of the exception is what SsoAction.logout writes to the log, and the
        // library puts the StatusCode of a failed LogoutResponse into the detail as the sender
        // wrote it.
        final SamlAuthenticator authenticator = createAuthenticator();
        setUpSlo();
        final MockletHttpServletRequest request = getMockRequest();
        redirect(request, "SAMLResponse", fresh(TestIdp.logoutResponseXml("_lr_forged", FORGED_STATUS_CODE)), true);

        final SsoMessageException e =
                Assertions.assertThrows(SsoMessageException.class, () -> authenticator.getResponse(SsoResponseType.LOGOUT));

        assertTrue(String.valueOf(e.getCause()), e.getCause() instanceof SsoStateException);
        final String message = e.getCause().getMessage();
        assertTrue(message, message.startsWith("STATUS_NOT_SUCCESS: "));
        assertTrue(message, message.contains("WARN forged line"));
        assertSafeForLog(message, SamlAuthenticator.MAX_LOGGED_FAILURE_REASON_LENGTH + 3);
    }

    @Test
    public void test_getLogoutResponse_refusesAMessageThatIsBothARequestAndAResponse() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticator();
        setUpSlo();
        final MockletHttpServletRequest request = getMockRequest();
        final String xml = fresh(TestIdp.logoutRequestXml("_both", USER, null));
        request.setMethod("GET");
        request.setParameter("SAMLRequest", TestIdp.deflate(xml));
        request.setParameter("SAMLResponse", TestIdp.deflate(fresh(TestIdp.logoutResponseXml("_both_response", SUCCESS))));
        request.setQueryString(TestIdp.redirectQuery("SAMLRequest", xml, null, TestIdp.IDP_KEY) + "&SAMLResponse="
                + URLEncoder.encode(TestIdp.deflate(fresh(TestIdp.logoutResponseXml("_both_response", SUCCESS))), StandardCharsets.UTF_8));
        request.getSession().setAttribute(SESSION_MARKER, "kept");

        final SsoMessageException e =
                Assertions.assertThrows(SsoMessageException.class, () -> authenticator.getResponse(SsoResponseType.LOGOUT));

        assertTrue(String.valueOf(e.getCause()), e.getCause() instanceof SsoStateException);
        assertTrue(e.getCause().getMessage(), e.getCause().getMessage().startsWith("BAD_REQUEST: "));
        assertEquals("kept", request.getSession(false).getAttribute(SESSION_MARKER));
    }

    @Test
    public void test_containsSamlLogoutMessage() throws Exception {
        final SamlAuthenticator authenticator = new SamlAuthenticator();

        assertFalse(authenticator.containsSamlLogoutMessage(getMockRequest()));

        final MockletHttpServletRequest blank = getMockRequest();
        blank.setParameter("SAMLRequest", "  ");
        assertFalse(authenticator.containsSamlLogoutMessage(blank));

        final MockletHttpServletRequest logoutRequest = getMockRequest();
        logoutRequest.setParameter("SAMLRequest", "PHNhbWxwOkxvZ291dFJlcXVlc3QgLz4=");
        assertTrue(authenticator.containsSamlLogoutMessage(logoutRequest));

        final MockletHttpServletRequest logoutResponse = getMockRequest();
        logoutResponse.setParameter("SAMLResponse", "PHNhbWxwOkxvZ291dFJlc3BvbnNlIC8+");
        assertTrue(authenticator.containsSamlLogoutMessage(logoutResponse));
    }

    @Test
    public void test_getLogoutResponse_keepsTheSessionWhenTheLogoutRequestNamesAnotherUser() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorLoggedInAs(samlUserBean(USER));
        setUpSlo();
        // /sso/logout is anonymous and SAML forces SameSite=none, so this request reaches the
        // endpoint cross-site with the session cookie of the user on it
        final MockletHttpServletRequest request = getMockRequest();
        request.getSession().setAttribute(SESSION_MARKER, "kept");
        sendLogoutRequest(request, "_other_user", OTHER_USER, true);

        final ActionResponse response = authenticator.getResponse(SsoResponseType.LOGOUT);

        assertEquals("kept", request.getSession(false).getAttribute(SESSION_MARKER));
        // the IdP still gets an ordinary LogoutResponse: an error would tell the sender
        // whether it guessed a live session, and would strand a confused-but-real IdP
        assertTrue(String.valueOf(response), String.valueOf(response).contains(TestIdp.SLO + "?SAMLResponse="));
    }

    @Test
    public void test_getLogoutResponse_endsTheSessionWhenTheLogoutRequestNamesTheSessionUser() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorLoggedInAs(samlUserBean(USER));
        setUpSlo();
        final MockletHttpServletRequest request = getMockRequest();
        request.getSession().setAttribute(SESSION_MARKER, "kept");
        sendLogoutRequest(request, "_session_user", USER, true);

        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            final ActionResponse response = authenticator.getResponse(SsoResponseType.LOGOUT);

            // the whole point of single logout: the IdP says so, so the session ends
            assertNull(request.getSession(false).getAttribute(SESSION_MARKER), "the session must not survive its own logout");
            assertTrue(String.valueOf(response), String.valueOf(response).contains(TestIdp.SLO + "?SAMLResponse="));
            assertTrue(String.valueOf(warnings(appender)), warnings(appender).isEmpty());
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_getLogoutResponse_keepsTheSessionWhenTheLogoutRequestNamesAnotherSessionOfTheUser() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorLoggedInAs(samlUserBean(USER));
        setUpSlo();
        final MockletHttpServletRequest request = getMockRequest();
        request.getSession().setAttribute(SESSION_MARKER, "kept");
        // the user is logged in as "_session1"; the IdP ends "_session2"
        redirect(request, "SAMLRequest", fresh(TestIdp.logoutRequestXml("_other_session", USER, "_session2")), true);

        authenticator.getResponse(SsoResponseType.LOGOUT);

        assertEquals("kept", request.getSession(false).getAttribute(SESSION_MARKER));
    }

    @Test
    public void test_getLogoutResponse_keepsTheSessionWhenNobodyIsLoggedIn() throws Exception {
        // With no session user there is nothing the LogoutRequest can name, so it ends nothing
        final SamlAuthenticator authenticator = createAuthenticatorLoggedInAs(OptionalThing.empty());
        setUpSlo();
        final MockletHttpServletRequest request = getMockRequest();
        request.getSession().setAttribute(SESSION_MARKER, "kept");
        sendLogoutRequest(request, "_anonymous", USER, true);

        final ActionResponse response = authenticator.getResponse(SsoResponseType.LOGOUT);

        assertEquals("kept", request.getSession(false).getAttribute(SESSION_MARKER));
        assertTrue(String.valueOf(response), String.valueOf(response).contains(TestIdp.SLO + "?SAMLResponse="));
    }

    @Test
    public void test_getLogoutResponse_keepsTheSessionOfAUserThatDidNotComeFromSaml() throws Exception {
        // A local or LDAP login carries a user name, not a NameID, and comparing the two would
        // end the session of a user the IdP knows nothing about.
        final SamlAuthenticator authenticator = createAuthenticatorLoggedInAs(OptionalThing.of(new FessUserBean(new LocalUser(USER))));
        setUpSlo();
        final MockletHttpServletRequest request = getMockRequest();
        request.getSession().setAttribute(SESSION_MARKER, "kept");
        sendLogoutRequest(request, "_local_user", USER, true);

        authenticator.getResponse(SsoResponseType.LOGOUT);

        assertEquals("kept", request.getSession(false).getAttribute(SESSION_MARKER));
    }

    @Test
    public void test_getLogoutResponse_refusesALogoutRequestThatNamesNobody() throws Exception {
        // An empty NameID is a message the sender can write at no cost, so it must not end a
        // session, and it is refused rather than answered: an error for it says nothing a sender
        // could use to find a live session.
        for (final String nameId : new String[] { "", "   ", "\n" }) {
            final SamlAuthenticator authenticator = createAuthenticatorLoggedInAs(samlUserBean(USER));
            setUpSlo();
            final MockletHttpServletRequest request = getMockRequest();
            request.getSession().setAttribute(SESSION_MARKER, "kept");
            sendLogoutRequest(request, "_empty" + nameId.length(), nameId, true);

            final SsoMessageException e =
                    Assertions.assertThrows(SsoMessageException.class, () -> authenticator.getResponse(SsoResponseType.LOGOUT));

            assertTrue(String.valueOf(e.getCause()), e.getCause() instanceof SsoStateException);
            assertEquals("a LogoutRequest that names nobody must not end a session", "kept",
                    request.getSession(false).getAttribute(SESSION_MARKER));
        }
    }

    @Test
    public void test_getLogoutResponse_neverEndsTheSessionForALogoutResponse() throws Exception {
        // The IdP answering a LogoutRequest this SP sent. The session of the user has been ended
        // by LogoutAction already when it arrives; whoever sends one to a live session must not
        // be able to end it.
        final SamlAuthenticator authenticator = createAuthenticatorLoggedInAs(samlUserBean(USER));
        setUpSlo();
        final MockletHttpServletRequest request = getMockRequest();
        request.getSession().setAttribute(SESSION_MARKER, "kept");
        redirect(request, "SAMLResponse", fresh(TestIdp.logoutResponseXml("_logout_response", SUCCESS)), true);

        final SsoMessageException e =
                Assertions.assertThrows(SsoMessageException.class, () -> authenticator.getResponse(SsoResponseType.LOGOUT));

        // the page that says the user is logged out
        assertEquals("Logged out", e.getMessage());
        assertEquals("kept", request.getSession(false).getAttribute(SESSION_MARKER));
    }

    @Test
    public void test_getLogoutResponse_refusesAReplayedLogoutRequest() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticatorLoggedInAs(samlUserBean(USER));
        setUpSlo();
        final MockletHttpServletRequest request = getMockRequest();
        sendLogoutRequest(request, "_replayed", USER, true);
        authenticator.getResponse(SsoResponseType.LOGOUT);

        final SsoMessageException e =
                Assertions.assertThrows(SsoMessageException.class, () -> authenticator.getResponse(SsoResponseType.LOGOUT));

        assertTrue(String.valueOf(e.getCause()), e.getCause() instanceof SsoStateException);
        assertTrue(e.getCause().getMessage(), e.getCause().getMessage().startsWith("REPLAYED: "));
    }

    @Test
    public void test_getSessionSamlUser_ignoresAUserThatDidNotComeFromSaml() throws Exception {
        // A local or LDAP login carries a user name, not a NameID, and comparing the two would
        // reject every legitimate single logout on a mixed-authentication deployment.
        final SamlUser samlUser = createAuthenticatorLoggedInAs(samlUserBean(USER)).getSessionSamlUser();
        assertNotNull(samlUser, "a SAML user");
        assertEquals(USER, samlUser.getName());
        assertNull(createAuthenticatorLoggedInAs(OptionalThing.of(new FessUserBean(new LocalUser(USER)))).getSessionSamlUser(),
                "a non-SAML user has no NameID to compare");
        assertNull(createAuthenticatorLoggedInAs(OptionalThing.empty()).getSessionSamlUser(), "nobody is logged in");
    }

    @Test
    public void test_getSessionSamlUser_answersNullWhenTheSessionCannotBeRead() throws Exception {
        final SamlAuthenticator authenticator = new SamlAuthenticator() {
            @Override
            protected OptionalThing<FessUserBean> getSavedUserBean() {
                throw new IllegalStateException("no login scope");
            }
        };

        // /sso/logout has to keep working for a request that reaches it outside a login scope, so
        // "cannot tell" must not become "fail" -- and must not become "logged in" either, which
        // would end a session on the word of whoever sent the request.
        assertNull(authenticator.getSessionSamlUser());
    }

    // ===================================================================================
    //                                                                              Logout
    //                                                                              ======
    @Test
    public void test_logout_buildsTheUrlOfTheIdp() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticator();
        setUpSlo();
        getMockRequest();
        final SamlUser user = new SamlUser(USER, "_session1", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", null, null,
                new String[0], new String[0]);

        final String url = authenticator.logout(new FessUserBean(user));

        assertNotNull(url, "the browser is sent to the IdP");
        assertTrue(url, url.startsWith(TestIdp.SLO + "?SAMLRequest="));
        assertTrue(url, url.contains("&SigAlg="));
        assertTrue(url, url.contains("&Signature="));
        final String message = redirectedMessage(url);
        assertTrue(message, message.contains(USER));
        assertTrue(message, message.contains("_session1"));
    }

    @Test
    public void test_logout_withoutIdpSingleLogoutServiceUrl() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticator();
        setUpLogin();
        getMockRequest();
        final SamlUser user = new SamlUser(USER, "_session1", null, null, null, new String[0], new String[0]);

        // single logout is optional: the user is logged out of Fess alone
        assertNull(authenticator.logout(new FessUserBean(user)));
    }

    @Test
    public void test_logout_ofAUserThatDidNotComeFromSaml() throws Exception {
        final SamlAuthenticator authenticator = createAuthenticator();
        setUpSlo();
        getMockRequest();

        assertNull(authenticator.logout(new FessUserBean(new LocalUser(USER))));
    }

    @Test
    public void test_logout_reportsAFailedSingleLogoutOnOneLine() throws Exception {
        // The single logout starts from the session of a logged-in user, and it fails whenever the
        // IdP settings no longer build. Each such logout would write a stack trace of dozens of
        // frames, none of which says more than the message does, so the WARN is one line and the
        // stack trace stays at debug level.
        final SamlAuthenticator authenticator = createAuthenticator();
        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            setUpSlo();
            ComponentUtil.getSystemProperties().remove("saml.idp.entityid");
            getMockRequest();
            final String nameId = "alice\n2099-01-01 00:00:00,000 [forged] ERROR FORGED";
            final SamlUser user = new SamlUser(nameId, "_session1", null, null, null, new String[0], new String[0]);

            assertNull(authenticator.logout(new FessUserBean(user)));

            final List<LogEvent> warns = appender.eventsAt(Level.WARN)
                    .stream()
                    .filter(e -> e.getMessage().getFormattedMessage().contains("Failed to logout from IdP"))
                    .toList();
            assertEquals(appender.renderedEvents().toString(), 1, warns.size());
            final LogEvent warn = warns.get(0);
            final String message = warn.getMessage().getFormattedMessage();
            assertNull(warn.getThrown(), message);
            assertFalse(message, message.contains("\n") || message.contains("\r"));
            assertTrue(message, message.contains("name=alice?2099"));
            assertTrue(message, message.contains("idp.entityid"));
            // the stack trace is still there for whoever turns debug on
            assertTrue(appender.eventsAt(Level.DEBUG)
                    .stream()
                    .anyMatch(e -> e.getThrown() != null && e.getMessage().getFormattedMessage().contains("Failed to logout from IdP")));
        } finally {
            appender.detach();
        }
    }

    // ===================================================================================
    //                                                                              Helper
    //                                                                              ======
    @Test
    public void test_sanitizeForLog_keepsAnUnauthenticatedNameIdFromForgingLogLines() throws Exception {
        // the NameID of the LogoutRequest is written to the log before anything has authenticated
        // the message, and it is XML text content, so it can carry a line break
        assertEquals("alice@example.com? ERROR forged", SamlAuthenticator.sanitizeForLog("alice@example.com\n ERROR forged"));
        assertEquals("alice@example.com? ERROR forged", SamlAuthenticator.sanitizeForLog("alice@example.com\r ERROR forged"));
        // \p{Cntrl} is ASCII-only, so the Unicode break characters a log viewer still renders as
        // a new line have to be covered separately
        assertEquals("a?b?c", SamlAuthenticator.sanitizeForLog("a\u0085b c"));

        final int max = SamlAuthenticator.MAX_LOGGED_NAME_ID_LENGTH;
        assertEquals("x".repeat(max) + "...", SamlAuthenticator.sanitizeForLog("x".repeat(max + 10)));
        // an ordinary NameID is passed through untouched
        assertEquals("alice@example.com", SamlAuthenticator.sanitizeForLog("alice@example.com"));

        // a rejection reason quotes the message it objected to, so it is sender-supplied in the
        // same way and gets the same treatment at a bound that leaves the sentence readable
        final int reasonMax = SamlAuthenticator.MAX_LOGGED_FAILURE_REASON_LENGTH;
        assertTrue(String.valueOf(reasonMax), reasonMax > max);
        assertEquals("the issuer is not the identity provider: ?ERROR forged",
                SamlAuthenticator.sanitizeForLog("the issuer is not the identity provider: \nERROR forged", reasonMax));
        assertEquals("y".repeat(reasonMax) + "...", SamlAuthenticator.sanitizeForLog("y".repeat(reasonMax + 1), reasonMax));
    }

    @Test
    public void test_buildDefaultUrl_withDefaultBaseUrl() throws Exception {
        assertEquals("http://localhost:8080/sso/metadata", new SamlAuthenticator().buildDefaultUrl("/sso/metadata"));
    }

    @Test
    public void test_buildDefaultUrl_withCustomBaseUrl() throws Exception {
        final SamlAuthenticator authenticator = new SamlAuthenticator();
        ComponentUtil.getSystemProperties().setProperty(BASE_URL_KEY, "https://fess.example.com:8443");

        assertEquals("https://fess.example.com:8443/sso/metadata", authenticator.buildDefaultUrl("/sso/metadata"));
    }

    @Test
    public void test_buildDefaultUrl_withTrailingSlash() throws Exception {
        final SamlAuthenticator authenticator = new SamlAuthenticator();
        ComponentUtil.getSystemProperties().setProperty(BASE_URL_KEY, "https://fess.example.com/");

        assertEquals("https://fess.example.com/sso/", authenticator.buildDefaultUrl("/sso/"));
    }

    @Test
    public void test_buildDefaultUrl_withBlankProperty() throws Exception {
        final SamlAuthenticator authenticator = new SamlAuthenticator();
        ComponentUtil.getSystemProperties().setProperty(BASE_URL_KEY, "   ");

        assertEquals("http://localhost:8080/sso/logout", authenticator.buildDefaultUrl("/sso/logout"));
    }
}
