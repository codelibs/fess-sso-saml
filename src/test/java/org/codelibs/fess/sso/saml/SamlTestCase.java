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

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.zip.Inflater;

import org.codelibs.core.misc.DynamicProperties;
import org.codelibs.fess.entity.FessUser;
import org.codelibs.fess.helper.SystemHelper;
import org.codelibs.fess.mylasta.action.FessUserBean;
import org.codelibs.fess.sso.saml.SamlCredential.SamlUser;
import org.codelibs.fess.unit.UnitFessTestCase;
import org.codelibs.fess.util.ComponentUtil;
import org.dbflute.optional.OptionalThing;
import org.dbflute.utflute.mocklet.MockletHttpServletRequest;
import org.junit.jupiter.api.TestInfo;

import jakarta.servlet.http.HttpSession;

/**
 * What the tests of the SAML authenticator share: the {@code saml.*} properties that make a working
 * configuration, the identity provider of {@link TestIdp} that signs the messages, and the helpers that put them
 * on the mock request.
 *
 * <p>The messages of {@link TestIdp} are stamped with a fixed instant. The library compares them with the clock of
 * its configuration, which the authenticator does not let a test replace, so the helpers here write the validity
 * periods relative to the time of the test (the library allows a drift of two minutes and the periods are five
 * minutes long). That keeps the whole path of the authenticator under test, including the service provider it
 * caches and the replay cache it keeps.</p>
 */
public abstract class SamlTestCase extends UnitFessTestCase {

    /** The key of the base URL of this service provider. */
    protected static final String BASE_URL_KEY = "saml.sp.base.url";

    /** A base URL that gives {@link TestIdp#SP}, {@link TestIdp#ACS} and {@link TestIdp#SLS}. */
    protected static final String BASE_URL = "https://fess.example.com";

    /** The name of the user the identity provider of {@link TestIdp} authenticates. */
    protected static final String USER = "alice@example.com";

    /** Another user. */
    protected static final String OTHER_USER = "bob@example.com";

    /** The session attribute that holds the pending AuthnRequest IDs. */
    protected static final String SAML_STATE = "SAML_STATE";

    /** Lets a test move the clock that pending AuthnRequest ID expiry is measured against. */
    protected final AtomicLong clock = new AtomicLong(1_000_000L);

    @Override
    protected void tearDown(final TestInfo testInfo) throws Exception {
        // a leftover saml.* key would reach the next test, and the library refuses a key it does not know
        final DynamicProperties systemProperties = ComponentUtil.getSystemProperties();
        for (final Object key : new ArrayList<>(systemProperties.keySet())) {
            if (String.valueOf(key).startsWith("saml.")) {
                systemProperties.remove(key);
            }
        }
        super.tearDown(testInfo);
    }

    // ===================================================================================
    //                                                                      Authenticator
    //                                                                      =============

    /**
     * Gives an authenticator the settings init() would give it. init() is not usable here because it registers
     * the instance with the SsoManager.
     *
     * @param authenticator the authenticator
     * @param <T> its type
     * @return the same authenticator
     */
    protected <T extends SamlAuthenticator> T withDefaultSettings(final T authenticator) {
        try {
            final Field field = SamlAuthenticator.class.getDeclaredField("defaultSettings");
            field.setAccessible(true);
            field.set(authenticator, authenticator.createDefaultSettings());
        } catch (final ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
        return authenticator;
    }

    /**
     * Builds an authenticator whose defaultSettings come from the production code.
     *
     * @return the authenticator
     */
    protected SamlAuthenticator createAuthenticator() {
        return withDefaultSettings(new SamlAuthenticator());
    }

    /**
     * Builds an authenticator that reports the given user as logged in. The real {@code FessLoginAssist} cannot
     * be resolved here because it injects the user index, which is exactly why reading the session user sits
     * behind an overridable method.
     *
     * @param userBean the user bean of the session
     * @return the authenticator
     */
    protected SamlAuthenticator createAuthenticatorLoggedInAs(final OptionalThing<FessUserBean> userBean) {
        return withDefaultSettings(new SamlAuthenticator() {
            @Override
            protected OptionalThing<FessUserBean> getSavedUserBean() {
                return userBean;
            }
        });
    }

    /**
     * Builds an authenticator and registers the system helper whose clock is {@link #clock}. Recording the
     * AuthnRequest ID stamps it with the clock of the system helper, which test_app.xml does not register.
     *
     * @return the authenticator
     */
    protected SamlAuthenticator createAuthenticatorWithControlledClock() {
        registerSystemHelper();
        return createAuthenticator();
    }

    /** Registers a system helper whose clock is {@link #clock}. */
    protected void registerSystemHelper() {
        ComponentUtil.register(new SystemHelper() {
            @Override
            public long getCurrentTimeAsLong() {
                return clock.get();
            }

            @Override
            public String getSearchRoleByDirectoryUser(final String name) {
                return "U" + name;
            }

            @Override
            public String getSearchRoleByDirectoryGroup(final String name) {
                return "G" + name;
            }

            @Override
            public String getSearchRoleByDirectoryRole(final String name) {
                return "R" + name;
            }
        }, "systemHelper");
    }

    // ===================================================================================
    //                                                                         Properties
    //                                                                         ==========

    /** Sets the identity provider of {@link TestIdp}. */
    protected void setUpIdp() {
        final DynamicProperties systemProperties = ComponentUtil.getSystemProperties();
        systemProperties.setProperty("saml.idp.entityid", TestIdp.IDP);
        systemProperties.setProperty("saml.idp.single_sign_on_service.url", TestIdp.SSO);
        systemProperties.setProperty("saml.idp.x509cert", TestIdp.pem("idp"));
    }

    /** Sets the base URL that gives the URLs {@link TestIdp} addresses. */
    protected void setUpBaseUrl() {
        ComponentUtil.getSystemProperties().setProperty(BASE_URL_KEY, BASE_URL);
    }

    /** The identity provider, the base URL and the single logout service, with the key pair of the service provider. */
    protected void setUpSlo() {
        setUpIdp();
        setUpBaseUrl();
        final DynamicProperties systemProperties = ComponentUtil.getSystemProperties();
        systemProperties.setProperty("saml.idp.single_logout_service.url", TestIdp.SLO);
        systemProperties.setProperty("saml.sp.x509cert", TestIdp.pem("sp"));
        systemProperties.setProperty("saml.sp.privatekey", TestIdp.keyPem("sp"));
    }

    /** Everything a login needs. */
    protected void setUpLogin() {
        setUpIdp();
        setUpBaseUrl();
    }

    // ===================================================================================
    //                                                                           Sessions
    //                                                                           ========

    /**
     * Reads the pending AuthnRequest IDs out of the session without assuming the shape of the attribute, so that
     * the same assertion can be run against the release that stored a single ID as a bare String.
     *
     * @param session the session, or null
     * @return the pending IDs, oldest first when the map is ordered
     */
    protected Set<String> pendingRequestIds(final HttpSession session) {
        final Object value = session == null ? null : session.getAttribute(SAML_STATE);
        if (value instanceof final Map<?, ?> requestIdMap) {
            return requestIdMap.keySet().stream().map(String::valueOf).collect(Collectors.toCollection(LinkedHashSet::new));
        }
        if (value instanceof final String requestId) {
            return new LinkedHashSet<>(List.of(requestId));
        }
        return new LinkedHashSet<>();
    }

    /**
     * Starts a login on the request, as an anonymous visit of /sso/ does.
     *
     * @param authenticator the authenticator
     * @param request the request
     * @return the ID of the AuthnRequest that was sent to the IdP
     */
    protected String startLogin(final SamlAuthenticator authenticator, final MockletHttpServletRequest request) {
        final Set<String> before = pendingRequestIds(request.getSession(false));
        authenticator.getLoginCredential();
        final Set<String> after = new LinkedHashSet<>(pendingRequestIds(request.getSession(false)));
        after.removeAll(before);
        assertEquals(1, after.size(), String.valueOf(after));
        return after.iterator().next();
    }

    /**
     * Records an AuthnRequest ID the way the start of a login does, without sending anything.
     *
     * @param session the session
     * @param requestId the ID
     */
    protected void addPendingRequestId(final HttpSession session, final String requestId) {
        final SamlAuthenticator authenticator = createAuthenticator();
        authenticator.storeRequestIdInSession(session, requestId);
    }

    // ===================================================================================
    //                                                                           Messages
    //                                                                           ========

    /**
     * Builds a response the identity provider of {@link TestIdp} signed, valid at the time of the test.
     *
     * @param requestId the ID of the request it answers
     * @param tweak what the test changes, or null
     * @return the response, as the {@code SAMLResponse} parameter
     */
    protected String signedResponse(final String requestId, final Consumer<TestIdp.ResponseSpec> tweak) {
        final TestIdp.ResponseSpec spec = TestIdp.response();
        spec.requestId = requestId;
        final Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        spec.issueInstant = now;
        spec.notBefore = now.minusSeconds(60);
        spec.notOnOrAfter = now.plusSeconds(300);
        spec.confirmationNotOnOrAfter = now.plusSeconds(300);
        if (tweak != null) {
            tweak.accept(spec);
        }
        return spec.encoded();
    }

    /**
     * Posts a response to the assertion consumer service.
     *
     * @param request the request the IdP is pretending to post to
     * @param samlResponse the {@code SAMLResponse} parameter
     */
    protected void post(final MockletHttpServletRequest request, final String samlResponse) {
        request.setMethod("POST");
        request.setParameter("SAMLResponse", samlResponse);
    }

    /**
     * Puts a message of the IdP on the request the way a redirect delivers it: the library reads the raw query
     * string and the authenticator looks at the parameters.
     *
     * @param request the request
     * @param param {@code SAMLRequest} or {@code SAMLResponse}
     * @param xml the message
     * @param signed whether the IdP signs it
     */
    protected void redirect(final MockletHttpServletRequest request, final String param, final String xml, final boolean signed) {
        request.setMethod("GET");
        request.setParameter(param, TestIdp.deflate(xml));
        request.setQueryString(TestIdp.redirectQuery(param, xml, null, signed ? TestIdp.IDP_KEY : null));
    }

    /**
     * Puts a LogoutRequest of the IdP on the request.
     *
     * @param request the request
     * @param id the ID of the message
     * @param nameId the NameID it asks to log out
     * @param signed whether the IdP signs it
     */
    protected void sendLogoutRequest(final MockletHttpServletRequest request, final String id, final String nameId, final boolean signed) {
        redirect(request, "SAMLRequest", fresh(TestIdp.logoutRequestXml(id, nameId, null)), signed);
    }

    /**
     * Gives a message of {@link TestIdp} the time of the test as its issue instant.
     *
     * @param xml the message
     * @return the message
     */
    protected static String fresh(final String xml) {
        return xml.replace(TestIdp.NOW.toString(), Instant.now().truncatedTo(ChronoUnit.SECONDS).toString());
    }

    /**
     * Reads the XML of the request an authenticator redirects the browser to.
     *
     * @param redirectUrl the URL
     * @return the XML
     */
    protected static String redirectedMessage(final String redirectUrl) {
        final String query = redirectUrl.substring(redirectUrl.indexOf('?') + 1);
        for (final String pair : query.split("&")) {
            if (pair.startsWith("SAMLRequest=") || pair.startsWith("SAMLResponse=")) {
                try {
                    final byte[] deflated =
                            Base64.getDecoder().decode(URLDecoder.decode(pair.substring(pair.indexOf('=') + 1), StandardCharsets.UTF_8));
                    final Inflater inflater = new Inflater(true);
                    inflater.setInput(deflated);
                    final ByteArrayOutputStream out = new ByteArrayOutputStream();
                    final byte[] buffer = new byte[4096];
                    while (!inflater.finished()) {
                        final int n = inflater.inflate(buffer);
                        if (n == 0 && (inflater.needsInput() || inflater.needsDictionary())) {
                            break;
                        }
                        out.write(buffer, 0, n);
                    }
                    inflater.end();
                    return out.toString(StandardCharsets.UTF_8);
                } catch (final java.util.zip.DataFormatException e) {
                    throw new IllegalStateException(e);
                }
            }
        }
        throw new IllegalStateException("no SAML message in " + redirectUrl);
    }

    /**
     * Builds the session bean a SAML login leaves behind; SamlUser.getName() is the NameID.
     *
     * @param nameId the NameID
     * @return the bean
     */
    protected static OptionalThing<FessUserBean> samlUserBean(final String nameId) {
        return OptionalThing.of(new FessUserBean(new SamlUser(nameId, "_session1", null, null, null, new String[0], new String[0])));
    }

    /** A user that did not authenticate through SAML, as a local or LDAP login leaves behind. */
    protected static class LocalUser implements FessUser {

        private static final long serialVersionUID = 1L;

        private final String name;

        /**
         * @param name the user name
         */
        protected LocalUser(final String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public String[] getRoleNames() {
            return new String[0];
        }

        @Override
        public String[] getGroupNames() {
            return new String[0];
        }

        @Override
        public String[] getPermissions() {
            return new String[0];
        }

    }
}
