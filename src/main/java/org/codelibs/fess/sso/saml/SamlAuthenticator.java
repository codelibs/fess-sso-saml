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

import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.codelibs.core.lang.StringUtil;
import org.codelibs.core.misc.DynamicProperties;
import org.codelibs.fess.app.web.base.login.ActionResponseCredential;
import org.codelibs.fess.app.web.base.login.FessLoginAssist.LoginCredentialResolver;
import org.codelibs.fess.crawler.Constants;
import org.codelibs.fess.exception.SsoLoginException;
import org.codelibs.fess.exception.SsoMessageException;
import org.codelibs.fess.exception.SsoProcessException;
import org.codelibs.fess.exception.SsoStateException;
import org.codelibs.fess.mylasta.action.FessUserBean;
import org.codelibs.fess.session.SessionDataSerializer;
import org.codelibs.fess.sso.SsoAuthenticator;
import org.codelibs.fess.sso.SsoResponseType;
import org.codelibs.fess.sso.saml.SamlCredential.SamlUser;
import org.codelibs.fess.util.ComponentUtil;
import org.codelibs.saml4j.InMemoryReplayCache;
import org.codelibs.saml4j.LoginResult;
import org.codelibs.saml4j.LoginStart;
import org.codelibs.saml4j.LogoutOutcome;
import org.codelibs.saml4j.NameId;
import org.codelibs.saml4j.Reason;
import org.codelibs.saml4j.ReplayCache;
import org.codelibs.saml4j.SamlConfig;
import org.codelibs.saml4j.SamlConfigException;
import org.codelibs.saml4j.ServiceProvider;
import org.dbflute.optional.OptionalEntity;
import org.dbflute.optional.OptionalThing;
import org.lastaflute.core.message.UserMessages;
import org.lastaflute.web.login.credential.LoginCredential;
import org.lastaflute.web.response.ActionResponse;
import org.lastaflute.web.response.HtmlResponse;
import org.lastaflute.web.response.StreamResponse;
import org.lastaflute.web.util.LaRequestUtil;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

/**
 * Authenticator for SAML 2.0.
 *
 * <p>This authenticator enables Single Sign-On (SSO) using SAML 2.0 protocol
 * with Identity Providers such as Okta, Entra ID, Keycloak, OneLogin, etc.</p>
 *
 * <h2>Required Configuration</h2>
 * <p>Add the following properties to {@code system.properties}:</p>
 * <pre>
 * # Enable SAML SSO
 * sso.type=saml
 *
 * # Identity Provider settings (obtain from your IdP)
 * saml.idp.entityid=http://www.okta.com/xxxxx
 * saml.idp.single_sign_on_service.url=https://your-domain.okta.com/app/xxxxx/sso/saml
 * saml.idp.x509cert=MIIDqjCCApKgAwIBAgIGAYMwfYAwMA0G...
 *
 * # SP base URL; the entity ID, the assertion consumer service and the single logout service are derived from it
 * saml.sp.base.url=https://your-fess-server.example.com
 * </pre>
 *
 * <p>{@code saml.sp.entityid}, {@code saml.sp.assertion_consumer_service.url} and
 * {@code saml.sp.single_logout_service.url} set the individual URLs when they differ. The URLs the IdP
 * is registered with are the ones the responses are checked against.</p>
 *
 * <h2>Optional Configuration</h2>
 * <pre>
 * # User attribute mapping
 * saml.attribute.group.name=groups
 * saml.attribute.role.name=roles
 *
 * # Default groups/roles for authenticated users
 * saml.default.groups=user
 * saml.default.roles=user
 *
 * # Single logout: the IdP URL (the SP URL is derived from saml.sp.base.url)
 * saml.idp.single_logout_service.url=https://your-domain.okta.com/app/xxxxx/slo/saml
 * </pre>
 *
 * <p>The keys that {@code saml4j} reads are listed in its {@code SamlConfig}. A key it does not know is
 * refused, so that a mistyped security setting cannot go unnoticed. Logout messages from the IdP must be signed
 * ({@code saml.security.want_logout_signed=true}, the default) and the IdP certificate is the only trust anchor.</p>
 *
 * <h2>Session Cookie Settings (Required)</h2>
 * <p>The IdP returns the assertion as a cross-site POST to the assertion consumer service.
 * A {@code SameSite=Lax} cookie is not sent on such a request, so the shipped default in
 * {@code tomcat_config.properties} has to be changed for SAML:</p>
 * <pre>
 * tomcat.sameSiteCookies = none
 * </pre>
 * <p>{@code none} is only accepted by browsers on a {@code Secure} cookie, so Fess must be
 * served over HTTPS.</p>
 *
 * @see <a href="https://fess.codelibs.org/">Fess Documentation</a>
 */
public class SamlAuthenticator implements SsoAuthenticator {

    /**
     * Constructor.
     */
    public SamlAuthenticator() {
    }

    private static final Logger logger = LogManager.getLogger(SamlAuthenticator.class);

    /**
     * The prefix for SAML properties.
     */
    protected static final String SAML_PREFIX = "saml.";

    /**
     * The session key holding the IDs of the AuthnRequests sent to the IdP that have not been
     * answered yet. Each ID is compared with the InResponseTo of the SAML response.
     *
     * <p>The value is a {@code Map<String, Long>} of AuthnRequest ID to the time it was created,
     * not a single ID: a browser with several tabs open sends one AuthnRequest per tab, and a
     * single slot means the second overwrites the first. The key is unchanged from the release
     * that stored a bare {@link String} here, so that an existing session keeps working across an
     * upgrade; see {@link #getRequestIdMap(HttpSession)} for how such a value is migrated.</p>
     */
    protected static final String SAML_STATE = "SAML_STATE";

    /**
     * The name of the component of Fess that serializes the attributes of a session for the session store.
     */
    protected static final String SESSION_DATA_SERIALIZER = "sessionDataSerializer";

    /**
     * The property key for the SAML SP base URL.
     */
    protected static final String SAML_SP_BASE_URL = "saml.sp.base.url";

    /** Upper bound on the length of a sender-supplied NameID embedded in a log message. */
    protected static final int MAX_LOGGED_NAME_ID_LENGTH = 64;

    /** Upper bound on the length of a rejection reason embedded in a log message. */
    protected static final int MAX_LOGGED_FAILURE_REASON_LENGTH = 512;

    /**
     * Characters that must not be copied verbatim into a log message. {@code \p{Cntrl}} alone is
     * ASCII-only, so the Unicode break characters a log viewer still renders as a new line are
     * listed explicitly.
     */
    private static final Pattern LOG_UNSAFE_PATTERN = Pattern.compile("[\\p{Cntrl}\\u0085\\u2028\\u2029]");

    /**
     * The properties under {@code saml.} that this authenticator reads itself; they are not passed to the library.
     */
    private static final Set<String> PLUGIN_KEYS = Set.of("sp.base.url", "request.id.ttl", "session.end_with_idp", "attribute.group.name",
            "attribute.role.name", "default.groups", "default.roles");

    /**
     * The {@code saml.} properties that earlier releases read and that no longer mean anything, with what to use
     * instead. They are dropped with one warning rather than refused, so that an upgrade does not stop every login
     * over a key that was only ever a permission. Anything else that is not known is refused when the settings are
     * built.
     */
    private static final Map<String, String> RETIRED_KEYS = retiredKeys();

    private static Map<String, String> retiredKeys() {
        final Map<String, String> keys = new java.util.TreeMap<>();
        for (final String key : new String[] { "compress.request", "compress.response", "contacts.support.email_address",
                "contacts.support.given_name", "contacts.technical.email_address", "contacts.technical.given_name",
                "idp.single_logout_service.binding", "idp.single_logout_service.response.url", "idp.single_sign_on_service.binding",
                "keystore.alias", "keystore.key.password", "keystore.store", "organization.displayname", "organization.lang",
                "organization.name", "organization.url", "parsing.trim_attribute_values", "parsing.trim_name_ids",
                "security.digest_algorithm", "security.logoutrequest_signed", "security.logoutresponse_signed", "security.nameid_encrypted",
                "security.nameid_encryption_algorithm", "security.reject_unsolicited_responses_with_inresponseto", "security.sign_metadata",
                "security.want_nameid", "security.want_nameid_encrypted", "security.want_xml_validation",
                "sp.assertion_consumer_service.binding", "sp.contact", "sp.single_logout_service.binding", "sp.x509certNew",
                "unique_id_prefix" }) {
            keys.put(key, "it is no longer used");
        }
        keys.put("idp.certfingerprint", "use saml.idp.x509cert; a fingerprint is no longer a trust anchor");
        keys.put("idp.certfingerprint_algorithm", "use saml.idp.x509cert; a fingerprint is no longer a trust anchor");
        keys.put("security.allow_duplicated_attribute_name", "repeated attributes are always merged");
        keys.put("security.allowed_key_transport_algorithms",
                "only OAEP is accepted; saml.security.allow_rsa_1_5=true accepts RSA 1.5 as well");
        keys.put("security.reject_deprecated_alg", "SHA-1 is rejected by default; saml.security.allow_deprecated_alg=true accepts it");
        keys.put("security.reject_missing_audience", "an assertion with no audience is always rejected");
        return java.util.Collections.unmodifiableMap(keys);
    }

    private final AtomicReference<Set<String>> loggedRetiredKeys = new AtomicReference<>();

    /**
     * The property key for how long, in seconds, an unanswered AuthnRequest ID stays usable. Only
     * a positive value is honoured; see {@link #getRequestIdTtl()}.
     */
    protected static final String SAML_REQUEST_ID_TTL = "saml.request.id.ttl";

    /**
     * The property key that says whether a login session ends when the identity provider says its session ends
     * ({@code SessionNotOnOrAfter}). Anything but {@code false} keeps it on; see {@link #isSessionEndWithIdp()}.
     */
    protected static final String SAML_SESSION_END_WITH_IDP = "saml.session.end_with_idp";

    /**
     * The time-to-live applied to an unanswered AuthnRequest ID when
     * {@link #SAML_REQUEST_ID_TTL} is absent, blank, not a number, or not positive. One hour.
     */
    protected static final String DEFAULT_REQUEST_ID_TTL = "3600";

    /**
     * The number of unanswered AuthnRequest IDs kept per session when {@code fess_sso++.xml}
     * leaves the cap alone, and the value {@link #setMaxRequestIds} falls back to when the
     * configured one is not positive.
     */
    protected static final int DEFAULT_MAX_REQUEST_IDS = 10;

    /**
     * Maximum number of unanswered AuthnRequest IDs kept per session. Every visit to
     * {@code /sso/} without a SAML response stores one, and {@code /sso/} is anonymous and
     * answers GET, so without a cap a page that embeds it as a sub-resource would grow the
     * session attribute without bound.
     *
     * <p>Always positive when it is set through {@link #setMaxRequestIds}, which is the only path
     * a configured value takes; a subclass that assigns the field directly is on its own.</p>
     */
    protected int maxRequestIds = DEFAULT_MAX_REQUEST_IDS;

    private Map<String, String> defaultSettings;

    /**
     * Cache of processed assertion IDs, used to reject replayed assertions.
     *
     * <p>The cache is held in memory by this instance and is not shared in a multi-instance
     * deployment. Without the session store of Fess (sticky sessions) the assertion has to reach
     * the instance whose session holds the matching AuthnRequest ID. With it
     * ({@code FESS_SESSION_STORE=opensearch}) any instance can answer, because the pending IDs are
     * shared. It is that ID check, not this cache, which rejects an assertion replayed to another
     * instance; the cache catches a repeated POST within a single session.</p>
     */
    private final ReplayCache replayCache = new InMemoryReplayCache();

    /**
     * The security warnings reported the last time they were logged, so that a settings
     * rebuild does not repeat them until the settings change.
     */
    private final AtomicReference<List<String>> loggedSecurityWarnings = new AtomicReference<>();

    /**
     * The most recently built service provider, paired with the properties it was built from.
     *
     * @param props the properties the service provider was built from
     * @param provider the service provider built from {@code props}
     */
    private record CachedProvider(Map<String, String> props, ServiceProvider provider) {
    }

    private final AtomicReference<CachedProvider> cachedProvider = new AtomicReference<>();

    /**
     * Initializes the SamlAuthenticator.
     */
    @PostConstruct
    public void init() {
        if (logger.isDebugEnabled()) {
            logger.debug("Initializing {}", this.getClass().getSimpleName());
        }
        ComponentUtil.getSsoManager().register(this);
        defaultSettings = createDefaultSettings();
        registerSessionSerializers();
    }

    /**
     * Tells the session store of Fess, which keeps the HTTP sessions of several nodes in OpenSearch when
     * {@code FESS_SESSION_STORE=opensearch} is set, how to write the user of a SAML login.
     *
     * <p>It has to run while the container initializes, before the store fixes the classes it knows, and it
     * is harmless when the store is not selected. A failure is logged and never stops the authenticator from
     * starting.</p>
     */
    protected void registerSessionSerializers() {
        try {
            if (!ComponentUtil.hasComponent(SESSION_DATA_SERIALIZER)) {
                return;
            }
            final SessionDataSerializer serializer = ComponentUtil.getComponent(SESSION_DATA_SERIALIZER);
            serializer.register(SamlUser.class, new SamlUserSerializer());
        } catch (final RuntimeException e) {
            logger.warn("The SAML user is not shared between nodes by the session store: {}", sanitizeForLog(String.valueOf(e)), e);
        }
    }

    /**
     * Creates the settings that are applied before the {@code saml.} system properties.
     *
     * @return The default settings, keyed without the {@code saml.} prefix.
     */
    protected Map<String, String> createDefaultSettings() {
        final Map<String, String> settings = new HashMap<>();
        settings.put("sp.nameidformat", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        settings.put("security.requested_authncontext", "urn:oasis:names:tc:SAML:2.0:ac:classes:Password");
        settings.put("security.requested_authncontextcomparison", "exact");
        return settings;
    }

    /**
     * Builds a default URL for SAML endpoints.
     * Uses the configured base URL or defaults to http://localhost:8080.
     *
     * @param path the path to append to the base URL
     * @return the complete URL
     */
    protected String buildDefaultUrl(final String path) {
        final DynamicProperties systemProperties = ComponentUtil.getSystemProperties();
        String baseUrl = systemProperties.getProperty(SAML_SP_BASE_URL);
        if (StringUtil.isBlank(baseUrl)) {
            baseUrl = "http://localhost:8080";
        }
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        return baseUrl + path;
    }

    /**
     * Builds the properties the configuration is read from, keyed without the {@code saml.} prefix.
     *
     * <p>A present-but-blank property is passed on as it is and counts as absent, which is what lets
     * {@code saml.security.requested_authncontext=} suppress the requested authentication context. The
     * three SP URLs are computed from {@code saml.sp.base.url} when they are not set, and the SP single
     * logout URL only when the IdP one is.</p>
     *
     * @return The properties for {@link SamlConfig#fromMap(Map)}.
     */
    protected Map<String, String> buildProperties() {
        return buildProperties(false);
    }

    /**
     * Builds the properties the configuration is read from.
     *
     * @param forMetadata true to build them for the SP metadata, which always names the single logout service
     * @return The properties.
     * @see #buildProperties()
     */
    protected Map<String, String> buildProperties(final boolean forMetadata) {
        final Map<String, String> params = new HashMap<>(defaultSettings);
        final Set<String> retired = new java.util.TreeSet<>();
        final DynamicProperties systemProperties = ComponentUtil.getSystemProperties();
        systemProperties.entrySet().forEach(e -> {
            final String key = e.getKey().toString();
            if (!key.startsWith(SAML_PREFIX)) {
                return;
            }
            final String name = key.substring(SAML_PREFIX.length());
            if (RETIRED_KEYS.containsKey(name)) {
                retired.add(name);
            } else if (!PLUGIN_KEYS.contains(name)) {
                params.put(name, e.getValue() == null ? "" : e.getValue().toString());
            }
        });
        logRetiredKeys(retired);
        fillUrl(params, "sp.entityid", "/sso/metadata");
        fillUrl(params, "sp.assertion_consumer_service.url", "/sso/");
        if (forMetadata) {
            fillUrl(params, "sp.single_logout_service.url", "/sso/logout");
        } else if (StringUtil.isBlank(params.get("idp.single_logout_service.url"))) {
            params.remove("sp.single_logout_service.url");
        } else {
            fillUrl(params, "sp.single_logout_service.url", "/sso/logout");
        }
        return params;
    }

    private void logRetiredKeys(final Set<String> retired) {
        if (retired.isEmpty() || retired.equals(loggedRetiredKeys.getAndSet(retired))) {
            return;
        }
        final String list = retired.stream().map(k -> SAML_PREFIX + k + " (" + RETIRED_KEYS.get(k) + ")").collect(Collectors.joining(", "));
        logger.warn("These SAML properties are no longer used and are ignored: {}", list);
    }

    private void fillUrl(final Map<String, String> params, final String key, final String path) {
        if (StringUtil.isBlank(params.get(key))) {
            params.put(key, buildDefaultUrl(path));
        }
    }

    /**
     * Gets the service provider for the properties currently in effect. It is rebuilt only when they change.
     *
     * @return The service provider.
     * @throws SamlConfigException if the properties do not make a valid configuration.
     */
    protected ServiceProvider getServiceProvider() {
        final Map<String, String> params = buildProperties();
        final CachedProvider cached = cachedProvider.get();
        if (cached != null && cached.props().equals(params)) {
            return cached.provider();
        }
        final SamlConfig config = SamlConfig.fromMap(params);
        final ServiceProvider provider = ServiceProvider.create(config, replayCache);
        logSecurityWarnings(config);
        cachedProvider.set(new CachedProvider(params, provider));
        return provider;
    }

    /**
     * Logs the settings that weaken the defaults. The warnings are logged again only when they change.
     *
     * @param config The configuration.
     */
    protected void logSecurityWarnings(final SamlConfig config) {
        final List<String> warnings = new java.util.ArrayList<>();
        if (config.singleLogoutServiceUrl() != null && !config.wantLogoutSigned()) {
            warnings.add("unsigned_logout_accepted");
        }
        if (config.allowDeprecatedAlg()) {
            warnings.add("deprecated_signature_algorithms_accepted");
        }
        if (config.allowRsa15()) {
            warnings.add("rsa_1_5_key_transport_accepted");
        }
        if (!warnings.equals(loggedSecurityWarnings.getAndSet(warnings)) && !warnings.isEmpty()) {
            logger.warn("Insecure SAML settings: {}. See the SAML SSO documentation for the recommended values.",
                    String.join(", ", warnings));
        }
    }

    @Override
    public LoginCredential getLoginCredential() {
        return LaRequestUtil.getOptionalRequest().map(request -> {
            if (logger.isDebugEnabled()) {
                logger.debug("Logging in with SAML Authenticator");
            }

            if (containsSamlResponse(request)) {
                final HttpSession session = request.getSession(false);
                // counted here rather than inside removeExpiredRequestIds so that the pruning
                // itself keeps the signature it ships with; see logUnmatchedSamlResponseAfterExpiry
                int expiredCount = 0;
                if (session != null) {
                    final Map<String, Long> requestIdMap = getRequestIdMap(session);
                    final int pendingCount = requestIdMap.size();
                    removeExpiredRequestIds(requestIdMap);
                    if (!requestIdMap.isEmpty()) {
                        try {
                            final LoginCredential credential = processSamlResponse(request, requestIdMap);
                            if (credential != null) {
                                // The ID is consumed. With a shared session store another request of this
                                // session may have replaced the attribute by a newer copy meanwhile, and
                                // that copy would still hold the ID and write it back. Putting the map
                                // that was consumed from back makes the consumption the state that is stored.
                                session.setAttribute(SAML_STATE, requestIdMap);
                            }
                            return credential;
                        } catch (final SamlConfigException e) {
                            logger.warn("Authentication failed: invalid SAML settings: {}",
                                    sanitizeForLog(e.getMessage(), MAX_LOGGED_FAILURE_REASON_LENGTH));
                            return null;
                        } catch (final Exception e) {
                            logger.warn("Authentication failed.", e);
                            return null;
                        }
                    }
                    // pruning is the only thing this thread removed, so an emptied map that was not
                    // empty a moment ago says how many logins ran out of time.
                    expiredCount = pendingCount;
                }
                // No session at all, or one that holds nothing still answerable: the assertion
                // cannot be tied to an AuthnRequest this server sent, so it is refused rather
                // than answered with another one.
                if (expiredCount > 0) {
                    logUnmatchedSamlResponseAfterExpiry(expiredCount);
                } else if (hasExpiredSession(request)) {
                    logUnmatchedSamlResponseAfterSessionExpiry();
                } else {
                    logUnmatchedSamlResponse(0);
                }
                return null;
            }

            try {
                final LoginStart start = getServiceProvider().startLogin();
                storeRequestIdInSession(request.getSession(), start.requestId());
                return new ActionResponseCredential(() -> HtmlResponse.fromRedirectPathAsIs(start.redirectUrl()));
            } catch (final SamlConfigException e) {
                // An SsoStateException: any anonymous request to /sso/ reaches this on a server whose IdP
                // settings are not complete, and SsoAction logs anything else with a stack trace.
                throw new SsoStateException(
                        "Failed to start a SAML login: " + sanitizeForLog(e.getMessage(), MAX_LOGGED_FAILURE_REASON_LENGTH), e);
            } catch (final Exception e) {
                throw new SsoLoginException("Invalid SAML redirect URL.", e);
            }

        }).orElse(null);
    }

    /**
     * Answers a SAML response with the pending AuthnRequest it names.
     *
     * <p>All pending IDs are handed to the library at once. It parses the response a single time and the
     * response has to answer one of them; the one it answered is consumed.</p>
     *
     * @param request The HTTP request carrying the SAML response.
     * @param requestIdMap The pending AuthnRequest IDs of the session, already pruned of expired
     *            entries. The matching entry is removed from it on success.
     * @return The login credential, or null when the response is not accepted.
     */
    protected LoginCredential processSamlResponse(final HttpServletRequest request, final Map<String, Long> requestIdMap) {
        final Set<String> candidates = new HashSet<>(getCandidateRequestIds(requestIdMap));
        final LoginResult result = getServiceProvider().finishLogin(request.getParameter("SAMLResponse"), candidates);
        if (result instanceof final LoginResult.Authenticated authenticated) {
            requestIdMap.remove(authenticated.requestId());
            return createLoginCredential(authenticated);
        }
        final LoginResult.Rejected rejected = (LoginResult.Rejected) result;
        if (rejected.reason() == Reason.WRONG_IN_RESPONSE_TO) {
            logUnmatchedSamlResponse(requestIdMap.size());
        } else {
            // Reported whatever the log level: the code alone says only that the login failed, and the detail
            // says what was objected to. It quotes the message, so the library bounds it and strips control
            // characters; this endpoint is anonymous.
            logger.warn("Authentication failed: {} - {}", rejected.reason(),
                    sanitizeForLog(rejected.detail(), MAX_LOGGED_FAILURE_REASON_LENGTH));
        }
        return null;
    }

    /**
     * Returns the pending AuthnRequest IDs to offer, most recently created first.
     *
     * <p>The list is capped at {@link #maxRequestIds} even though the map is already bounded on write, so that
     * lowering the cap at runtime takes effect on the very next response.</p>
     *
     * @param requestIdMap The pending AuthnRequest IDs of the session.
     * @return The AuthnRequest IDs to offer.
     */
    protected List<String> getCandidateRequestIds(final Map<String, Long> requestIdMap) {
        return requestIdMap.entrySet()
                .stream()
                .sorted(Comparator.comparingLong((final Map.Entry<String, Long> e) -> e.getValue()).reversed())
                .limit(maxRequestIds)
                .map(Map.Entry::getKey)
                .collect(Collectors.toList());
    }

    /**
     * Logs the one line reported when a SAML response cannot be tied to an AuthnRequest this
     * server sent.
     *
     * <p>It is a warning and not a redirect back to the IdP on purpose: answering an unmatched
     * assertion with a fresh AuthnRequest sends the browser to an IdP that is already
     * authenticated, which posts the same kind of unmatched assertion straight back, and the
     * loop only ends when the browser gives up.</p>
     *
     * <p>The SameSite guidance below is what this case usually is, but only because the two ways
     * a login can instead have run out of time are reported elsewhere: an ID pruned by
     * {@link #SAML_REQUEST_ID_TTL} by {@link #logUnmatchedSamlResponseAfterExpiry(int)}, and a
     * session the container has already discarded by
     * {@link #logUnmatchedSamlResponseAfterSessionExpiry()}. Without that split every expired
     * login would read as a cookie misconfiguration, since neither leaves anything pending and
     * both therefore reach this line with a pending count of zero as well.</p>
     *
     * @param pendingCount How many pending AuthnRequest IDs the session held, so that a log can
     *            tell a missing session cookie apart from a response that simply matched none of
     *            several live logins.
     */
    protected void logUnmatchedSamlResponse(final int pendingCount) {
        logger.warn("""
                Received a SAML response with no matching AuthnRequest ID in the session ({} pending).\
                 The assertion consumer service is a cross-site POST, which does not carry a SameSite=Lax cookie;\
                 see tomcat.sameSiteCookies in tomcat_config.properties.\
                 An IdP-initiated (unsolicited) response is rejected for the same reason.""", pendingCount);
    }

    /**
     * Logs the one line reported when a SAML response arrives after every AuthnRequest ID its
     * session held had passed {@link #SAML_REQUEST_ID_TTL}.
     *
     * <p>Kept apart from {@link #logUnmatchedSamlResponse(int)} because that line names
     * {@code tomcat.sameSiteCookies} as the cause, and here the session cookie demonstrably did
     * arrive: the session was found and it did hold pending IDs until this request pruned them.
     * Sending an operator whose cookie settings are already correct off to change them is what
     * the split avoids; the only line that told the two apart was the {@code debug} one in
     * {@link #removeExpiredRequestIds(Map)}, which is below the level a shipped Fess logs at.</p>
     *
     * <p>This is an ordinary event rather than a misconfiguration -- a user who starts a login and
     * finishes it at the IdP later than the TTL allows reaches it, and simply starting the login
     * again succeeds -- so it is worth telling apart from the cases that need an administrator.</p>
     *
     * <p>An extension that overrides {@link #logUnmatchedSamlResponse(int)} to reshape or suppress
     * that warning wants to override this one as well: until this method existed, the expiry case
     * was reported by that one with a pending count of zero.</p>
     *
     * @param expiredCount How many pending AuthnRequest IDs had expired, that is, how many logins
     *            the session still had in flight before the TTL removed them.
     */
    protected void logUnmatchedSamlResponseAfterExpiry(final int expiredCount) {
        logger.warn("""
                Received a SAML response after all {} pending AuthnRequest ID(s) of the session had expired.\
                 The session cookie did reach this server, so this is not the SameSite case:\
                 the login took longer to finish at the IdP than {} allows, and starting it again resolves it.""", expiredCount,
                SAML_REQUEST_ID_TTL);
    }

    /**
     * Logs the one line reported when a SAML response arrives with a session id the container no
     * longer recognises, so the session that held the AuthnRequest ID is gone rather than merely
     * empty.
     *
     * <p>This, not {@link #logUnmatchedSamlResponseAfterExpiry(int)}, is what a login left too
     * long at the IdP actually reaches on a stock Fess, because the session runs out first: the
     * AuthnRequest ID is kept for {@link #DEFAULT_REQUEST_ID_TTL} seconds, an hour, while
     * {@code WEB-INF/web.xml} sets no {@code session-timeout} and nothing calls
     * {@code setMaxInactiveInterval}, which leaves the servlet container's own default of thirty
     * minutes. The session is therefore discarded, IDs and all, some half an hour before any of
     * those IDs can expire, and the response comes back to a {@code getSession(false)} that
     * returns null. Without this line that lands on {@link #logUnmatchedSamlResponse(int)} and is
     * reported as a {@code SameSite} cookie problem -- the very misdiagnosis the expiry line was
     * added to prevent, in the one case that occurs in practice.</p>
     *
     * <p>The two are told apart by {@link #hasExpiredSession(HttpServletRequest)}: a browser that
     * is not sending the session cookie sends no session id at all, so a request that does carry
     * one demonstrably kept the cookie and lost only the session behind it.</p>
     *
     * <p>Like the TTL case this is an ordinary event rather than a misconfiguration, and starting
     * the login again resolves it. It names the container's session timeout instead of
     * {@link #SAML_REQUEST_ID_TTL} on purpose, since raising the TTL cannot extend a session that
     * is already the shorter of the two.</p>
     *
     * <p>An extension that overrides {@link #logUnmatchedSamlResponse(int)} to reshape or suppress
     * that warning wants to override this one as well: until this method existed, this case was
     * reported by that one with a pending count of zero.</p>
     */
    protected void logUnmatchedSamlResponseAfterSessionExpiry() {
        logger.warn("""
                Received a SAML response after the session it belongs to had expired.\
                 The browser did return its session cookie, so this is not the SameSite case:\
                 the session, and with it the AuthnRequest ID it held, was discarded by the\
                 container's session timeout rather than by {}, so raising that value does not help.\
                 Starting the login again resolves it.""", SAML_REQUEST_ID_TTL);
    }

    /**
     * Returns whether the request carries a session id that the container no longer recognises.
     *
     * <p>This is what tells an expired session apart from a browser that is not sending the
     * cookie: a request with no session id at all cannot have lost one. Named after the
     * {@code EntraIdAuthenticator} method that answers the same question, so that the two
     * authenticators stay recognisable to each other.</p>
     *
     * <p>Unlike there, the answer only chooses a log line here. An unmatched SAML response is
     * refused either way, because restarting the login by redirecting to an IdP that is already
     * authenticated would only bring the same unmatched assertion straight back.</p>
     *
     * @param request The HTTP servlet request.
     * @return True if a session id was sent and it is no longer valid.
     */
    protected boolean hasExpiredSession(final HttpServletRequest request) {
        return request.getRequestedSessionId() != null && !request.isRequestedSessionIdValid();
    }

    /**
     * Records the ID of an AuthnRequest that has just been sent to the IdP, pruning the entries
     * that can no longer be answered first.
     *
     * @param session The HTTP session.
     * @param requestId The ID of the AuthnRequest sent to the IdP.
     */
    protected void storeRequestIdInSession(final HttpSession session, final String requestId) {
        final Map<String, Long> requestIdMap = getRequestIdMap(session);
        removeExpiredRequestIds(requestIdMap);
        removeOldestRequestIds(requestIdMap, maxRequestIds - 1);
        if (logger.isDebugEnabled()) {
            logger.debug("Storing AuthnRequest ID in session: {}", requestId);
        }
        requestIdMap.put(requestId, ComponentUtil.getSystemHelper().getCurrentTimeAsLong());
        // see getLoginCredential: the map in hand must be the one the session holds when it is stored
        session.setAttribute(SAML_STATE, requestIdMap);
    }

    /**
     * Returns the per-session map of unanswered AuthnRequest IDs, creating it if needed.
     *
     * <p>The map is concurrent, and the create is synchronized on the session, because the tabs
     * that make several logins possible in the first place can also start them at the same
     * moment: a plain {@code HashMap} created twice loses the ID one of them has to match
     * later.</p>
     *
     * <p>Anything else found under the key is replaced rather than cast. A session that predates
     * this change holds a bare {@link String} there, and blindly casting it would end the login
     * with a {@link ClassCastException} rather than a message; that single ID is carried over so
     * a login already in flight across the upgrade can still complete.</p>
     *
     * <p>A map that the session store of Fess read back is checked the same way, because what it
     * holds is whatever the store held: an entry that is not a non-blank ID with the time it was
     * created is dropped, and only the newest {@link #maxRequestIds} entries are kept, so a damaged
     * or oversized value cannot fail the login with a {@link ClassCastException} or make it sort
     * an unbounded map. A map that needs no repair is returned as it is.</p>
     *
     * <p>{@code synchronized (session)} orders the requests of this session on this node only. When
     * the sessions are shared between nodes every node has its own session object, so two nodes
     * can still create the map, or consume the same ID, at the same moment; see
     * the README for what that does and does not allow.</p>
     *
     * @param session The HTTP session.
     * @return The AuthnRequest ID map held by the session, keyed by ID and valued with the time
     *         the ID was created.
     */
    protected Map<String, Long> getRequestIdMap(final HttpSession session) {
        synchronized (session) {
            final Object stored = session.getAttribute(SAML_STATE);
            if (stored instanceof final ConcurrentHashMap<?, ?> storedMap) {
                if (isValidRequestIdMap(storedMap)) {
                    @SuppressWarnings("unchecked")
                    final Map<String, Long> valid = (Map<String, Long>) storedMap;
                    return valid;
                }
                final Map<String, Long> repaired = repairRequestIdMap(storedMap);
                session.setAttribute(SAML_STATE, repaired);
                return repaired;
            }
            final Map<String, Long> concurrentMap = new ConcurrentHashMap<>();
            if (stored instanceof final String requestId && StringUtil.isNotBlank(requestId)) {
                concurrentMap.put(requestId, ComponentUtil.getSystemHelper().getCurrentTimeAsLong());
            }
            session.setAttribute(SAML_STATE, concurrentMap);
            return concurrentMap;
        }
    }

    /**
     * Tells whether every entry of a stored map is an ID with the time it was created, and the map is
     * not larger than {@link #maxRequestIds}.
     *
     * @param map The map found in the session.
     * @return true if it can be used as it is.
     */
    private boolean isValidRequestIdMap(final Map<?, ?> map) {
        if (map.size() > maxRequestIds) {
            return false;
        }
        return map.entrySet()
                .stream()
                .allMatch(e -> e.getKey() instanceof final String id && StringUtil.isNotBlank(id) && e.getValue() instanceof Long);
    }

    /**
     * Copies the valid entries of a stored map, the newest {@link #maxRequestIds} of them.
     *
     * @param map The map found in the session.
     * @return A new map.
     */
    private Map<String, Long> repairRequestIdMap(final Map<?, ?> map) {
        final Map<String, Long> repaired = new ConcurrentHashMap<>();
        map.entrySet()
                .stream()
                .filter(e -> e.getKey() instanceof final String id && StringUtil.isNotBlank(id) && e.getValue() instanceof Long)
                .sorted(Comparator.comparingLong((final Map.Entry<?, ?> e) -> (Long) e.getValue()).reversed())
                .limit(maxRequestIds)
                .forEach(e -> repaired.put((String) e.getKey(), (Long) e.getValue()));
        return repaired;
    }

    /**
     * Drops the AuthnRequest IDs that are older than the configured TTL.
     *
     * @param requestIdMap The AuthnRequest ID map to prune.
     */
    protected void removeExpiredRequestIds(final Map<String, Long> requestIdMap) {
        final long now = ComponentUtil.getSystemHelper().getCurrentTimeAsLong();
        final long requestIdTtl = getRequestIdTtl();
        requestIdMap.entrySet()
                .stream()
                // abs: a time ahead of this node's clock, from another node or a damaged value, must run out too
                .filter(e -> Math.abs(now - e.getValue()) / 1000L > requestIdTtl)
                .map(Map.Entry::getKey)
                .collect(Collectors.toList())
                .forEach(requestId -> {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Removing expired AuthnRequest ID: {}", requestId);
                    }
                    requestIdMap.remove(requestId);
                });
    }

    /**
     * Drops the least recently created AuthnRequest IDs until at most {@code limit} remain. An
     * AuthnRequest that is never answered does not expire before the TTL, so this is what bounds
     * the map for a client that keeps starting logins.
     *
     * @param requestIdMap The AuthnRequest ID map to prune.
     * @param limit The number of AuthnRequest IDs to keep.
     */
    protected void removeOldestRequestIds(final Map<String, Long> requestIdMap, final int limit) {
        if (requestIdMap.size() <= limit) {
            return;
        }
        requestIdMap.entrySet()
                .stream()
                .sorted(Comparator.comparingLong(Map.Entry::getValue))
                .limit((long) requestIdMap.size() - limit)
                .map(Map.Entry::getKey)
                .collect(Collectors.toList())
                .forEach(requestId -> {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Removing surplus AuthnRequest ID: {}", requestId);
                    }
                    requestIdMap.remove(requestId);
                });
    }

    /**
     * Sets the maximum number of unanswered AuthnRequest IDs kept per session.
     *
     * <p>A value that is not positive is reported and replaced by
     * {@link #DEFAULT_MAX_REQUEST_IDS} rather than taken literally, for the same reason
     * {@link #getRequestIdTtl()} refuses one. Nothing fails as it is applied, but
     * {@link #getCandidateRequestIds} hands it to {@code limit()}: {@code 0} leaves
     * {@link #processSamlResponse} no candidate to try, so every SAML login in the deployment
     * fails and is reported by {@link #logUnmatchedSamlResponse} as the cookie problem it is not,
     * and a negative value makes {@code limit()} throw an {@link IllegalArgumentException} that
     * reaches the log only as "Authentication failed.". {@code 0} is not a far-fetched value to
     * write either -- it reads as "no limit" -- which is why it falls back rather than being
     * taken at its word. The warning names the property and the value. Refusing it here is
     * enough because this setter is the only path a configured value takes; a subclass that
     * assigns the field directly bypasses the check.</p>
     *
     * @param maxRequestIds The maximum number of AuthnRequest IDs. Only a positive value is
     *                      honoured.
     */
    public void setMaxRequestIds(final int maxRequestIds) {
        if (maxRequestIds <= 0) {
            logger.warn("maxRequestIds must be a positive number: {}. Using {}.", maxRequestIds, DEFAULT_MAX_REQUEST_IDS);
            this.maxRequestIds = DEFAULT_MAX_REQUEST_IDS;
            return;
        }
        this.maxRequestIds = maxRequestIds;
    }

    /**
     * Gets how long an unanswered AuthnRequest ID stays usable.
     *
     * <p>A value that is not a number is reported once per read rather than thrown, because the
     * alternative is a login that dies with a {@code NumberFormatException} nobody can act
     * on.</p>
     *
     * <p>A value that is not positive is treated the same way, and for the same reason. It parses,
     * so nothing would fail here, but {@link #removeExpiredRequestIds} compares
     * {@code (now - created) / 1000} against it: {@code 0} drops an AuthnRequest ID one second
     * after it was issued and a negative value drops it at once, so no IdP round trip could ever
     * complete and every SAML login in the deployment would fail. {@code 0} is not a far-fetched
     * value to write either -- it reads as "no expiry", and elsewhere in Fess that is what it
     * means -- which is why it falls back rather than being taken literally. The warning names the
     * property and the value, and is worded differently from the one above so that a log says
     * which of the two mistakes was made.</p>
     *
     * @return The TTL in seconds, always positive. {@link #removeExpiredRequestIds} compares it
     *         against an elapsed time that has already been divided by 1000.
     */
    protected long getRequestIdTtl() {
        final long defaultTtl = Long.parseLong(DEFAULT_REQUEST_ID_TTL);
        final String value = ComponentUtil.getFessConfig().getSystemProperty(SAML_REQUEST_ID_TTL);
        if (StringUtil.isBlank(value)) {
            return defaultTtl;
        }
        final long requestIdTtl;
        try {
            requestIdTtl = Long.parseLong(value.trim());
        } catch (final NumberFormatException e) {
            logger.warn("Invalid {}: {}. Using {} seconds.", SAML_REQUEST_ID_TTL, value, DEFAULT_REQUEST_ID_TTL);
            return defaultTtl;
        }
        if (requestIdTtl <= 0) {
            logger.warn("{} must be a positive number of seconds: {}. Using {} seconds.", SAML_REQUEST_ID_TTL, value,
                    DEFAULT_REQUEST_ID_TTL);
            return defaultTtl;
        }
        return requestIdTtl;
    }

    /**
     * Returns whether the request carries a SAML response, which is what the IdP posts to the
     * assertion consumer service.
     *
     * <p>The session is deliberately not consulted here: it is the session cookie that goes
     * missing when the browser refuses to send it on the cross-site POST, and a callback that is
     * mistaken for a fresh visit is redirected back to the IdP forever.</p>
     *
     * <p>Only solicited responses are accepted. Fess binds every response to the ID of the
     * AuthnRequest it sent, so an unsolicited (IdP-initiated) response has nothing to match
     * against and is rejected rather than answered with a fresh AuthnRequest.</p>
     *
     * @param request The HTTP request.
     * @return true if the request carries a SAML response.
     */
    protected boolean containsSamlResponse(final HttpServletRequest request) {
        return StringUtil.isNotBlank(request.getParameter("SAMLResponse"));
    }

    /**
     * Creates a login credential.
     *
     * @param authenticated The accepted login.
     * @return The login credential.
     */
    protected LoginCredential createLoginCredential(final LoginResult.Authenticated authenticated) {
        final SamlCredential samlCredential = new SamlCredential(authenticated, getSessionExpiresAt(authenticated));
        if (logger.isDebugEnabled()) {
            logger.debug("SamlCredential: {}", samlCredential);
        }
        return samlCredential;
    }

    /**
     * Tells whether a login session ends when the identity provider says its session ends. It is on unless
     * {@code saml.session.end_with_idp} is {@code false}: a value that is not understood does not switch off a check
     * that keeps a session from outliving the one it came from.
     *
     * @return {@code true} if the session ends with the one of the identity provider.
     */
    protected boolean isSessionEndWithIdp() {
        final String value = ComponentUtil.getFessConfig().getSystemProperty(SAML_SESSION_END_WITH_IDP, "true");
        return value == null || !"false".equalsIgnoreCase(value.trim());
    }

    /**
     * Returns when the login session must end, in epoch milliseconds, or 0 when it has no end of its own.
     *
     * <p>The library accepts a login up to {@code clock_drift} seconds after the {@code SessionNotOnOrAfter} of the
     * assertion, so the same drift is added here: a login that was accepted is never expired by the first request,
     * and an identity provider whose clock is ahead cannot make the user log in again and again.</p>
     *
     * @param authenticated The accepted login.
     * @return The end of the session in epoch milliseconds, or 0.
     */
    protected long getSessionExpiresAt(final LoginResult.Authenticated authenticated) {
        if (authenticated.sessionNotOnOrAfter() == null || !isSessionEndWithIdp()) {
            return 0L;
        }
        return authenticated.sessionNotOnOrAfter().toEpochMilli() + getServiceProvider().config().clockDriftSeconds() * 1000L;
    }

    @Override
    public void resolveCredential(final LoginCredentialResolver resolver) {
        resolver.resolve(SamlCredential.class, credential -> OptionalEntity.of(credential.getUser()));
    }

    @Override
    public String logout(final FessUserBean user) {
        if (user.getFessUser() instanceof final SamlUser samlUser) {
            if (logger.isDebugEnabled()) {
                logger.debug("Logging out with SAML Authenticator");
            }
            try {
                final ServiceProvider provider = getServiceProvider();
                if (provider.config().idpSingleLogoutServiceUrl() == null) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("IdP single logout service URL is not configured, skipping SLO for user: {}", samlUser);
                    }
                    return null;
                }
                final NameId nameId = new NameId(samlUser.getName(), samlUser.getNameIdFormat(), samlUser.getNameidNameQualifier(),
                        samlUser.getNameidSPNameQualifier());
                return provider.startLogout(nameId, samlUser.getSessionIndex()).redirectUrl();
            } catch (final Exception e) {
                // Every logout of a logged-in user reaches this while the IdP settings do not build, so
                // the warning is one line and the stack trace stays at debug level.
                logger.warn("Failed to logout from IdP: name={} - {}", sanitizeForLog(String.valueOf(samlUser.getName())),
                        sanitizeForLog(String.valueOf(e.getMessage()), MAX_LOGGED_FAILURE_REASON_LENGTH));
                if (logger.isDebugEnabled()) {
                    logger.debug("Failed to logout from IdP.", e);
                }
            }
        }
        return null;
    }

    @Override
    public ActionResponse getResponse(final SsoResponseType responseType) {
        return switch (responseType) {
        case METADATA -> getMetadataResponse();
        case LOGOUT -> getLogoutResponse();
        default -> null;
        };
    }

    /**
     * Builds the exception used to report a failed SSO request to the user.
     *
     * @param action The action being performed, used as the log message.
     * @param msg The reason, shown to the user.
     * @param cause The underlying cause. An {@code SsoStateException} marks the failure as caused
     *        by the client, which {@code SsoAction} logs without a stack trace.
     * @return The exception to throw.
     */
    protected SsoMessageException processFailure(final String action, final String msg, final Exception cause) {
        return new SsoMessageException(messages -> messages.addErrorsFailedToProcessSsoRequest(UserMessages.GLOBAL_PROPERTY_KEY, msg),
                action, cause);
    }

    /**
     * Builds the exception used to report a failed SSO request that has no underlying exception.
     *
     * @param action The action being performed, used as the log message.
     * @param msg The reason, shown to the user.
     * @return The exception to throw.
     */
    protected SsoMessageException processFailure(final String action, final String msg) {
        return processFailure(action, msg, new SsoProcessException(msg));
    }

    /**
     * Builds the response that serves the service provider metadata as {@code metadata.xml}.
     *
     * <p>The SP metadata is what the IdP is registered from, so it has to be obtainable before
     * any {@code saml.idp.*} property exists: only the SP settings are validated.</p>
     *
     * @return the metadata response
     */
    protected ActionResponse getMetadataResponse() {
        return LaRequestUtil.getOptionalRequest().map(request -> {
            if (logger.isDebugEnabled()) {
                logger.debug("Accessing metadata with SAML Authenticator");
            }
            try {
                final String metadata = ServiceProvider.metadataOf(SamlConfig.fromMapForMetadata(buildProperties(true)));
                return new StreamResponse("metadata.xml").contentType("application/samlmetadata+xml").stream(out -> {
                    try (final Writer writer = new OutputStreamWriter(out.stream(), Constants.UTF_8_CHARSET)) {
                        writer.write(metadata);
                    }
                });
            } catch (final SamlConfigException e) {
                // an anonymous request to a server whose settings are invalid: one line, not a stack trace per request
                final String msg = sanitizeForLog(e.getMessage(), MAX_LOGGED_FAILURE_REASON_LENGTH);
                throw processFailure("Failed to process metadata.", msg, new SsoStateException(msg));
            } catch (final Exception e) {
                throw processFailure("Failed to process metadata.", e.getMessage(), e);
            }
        }).orElseThrow(() -> processFailure("Failed to process metadata.", "Invalid state."));
    }

    /**
     * Returns whether the request carries a SAML logout message, which is what the IdP sends to
     * the single logout service.
     *
     * @param request The HTTP request.
     * @return true if the request carries a SAML logout request or response.
     */
    protected boolean containsSamlLogoutMessage(final HttpServletRequest request) {
        return StringUtil.isNotBlank(request.getParameter("SAMLRequest")) || StringUtil.isNotBlank(request.getParameter("SAMLResponse"));
    }

    /**
     * Gets the logout response.
     *
     * <p>{@code /sso/logout} is anonymous and, because SAML requires {@code SameSite=none}, reachable
     * cross-site with the victim's session cookie attached. The library decides: a LogoutRequest ends the
     * session it names and no other, a session that did not come from SAML is never ended by one, and a
     * LogoutResponse never ends a session.</p>
     *
     * @return The logout response.
     */
    protected ActionResponse getLogoutResponse() {
        return LaRequestUtil.getOptionalRequest().<ActionResponse> map(request -> {
            if (logger.isDebugEnabled()) {
                logger.debug("Logging out with SAML Authenticator");
            }
            try {
                if (!containsSamlLogoutMessage(request)) {
                    final String msg = "The request carries no SAML logout message.";
                    throw processFailure("Failed to log out.", msg, new SsoStateException(msg));
                }
                final ServiceProvider provider = getServiceProvider();
                if (provider.config().singleLogoutServiceUrl() == null) {
                    throw processFailure("Failed to log out.", "IdP single logout service URL is not configured.");
                }
                final SamlUser samlUser = getSessionSamlUser();
                final String sessionNameId = samlUser == null ? null : samlUser.getName();
                final String sessionIndex = samlUser == null ? null : samlUser.getSessionIndex();
                // The IdP sends the message with the binding the SP metadata names for it, and an IdP such as
                // Keycloak posts it by default: the redirect binding carries it in the query string, the POST
                // binding in the form.
                final LogoutOutcome outcome = "POST".equalsIgnoreCase(request.getMethod())
                        ? provider.handleLogoutPost(request.getParameter("SAMLRequest"), request.getParameter("SAMLResponse"),
                                request.getParameter("RelayState"), sessionNameId, sessionIndex)
                        : provider.handleLogout(request.getMethod(), request.getQueryString(), sessionNameId, sessionIndex);
                if (outcome.action() == LogoutOutcome.Action.REJECTED) {
                    // The detail quotes the sender's own input, so it only goes to the log (SsoAction logs it without a
                    // stack trace). /sso/logout is anonymous and reachable cross-site: showing the detail on the login
                    // page would let anyone put text of their choosing there. The user sees the reason code only.
                    final String msg = sanitizeForLog(outcome.reason() + ": " + outcome.detail(), MAX_LOGGED_FAILURE_REASON_LENGTH);
                    throw processFailure("Failed to log out.", String.valueOf(outcome.reason()), new SsoStateException(msg));
                }
                if (outcome.action() == LogoutOutcome.Action.KEEP_SESSION && samlUser != null && outcome.redirectUrl() != null) {
                    logger.warn("The LogoutRequest does not name this session's user, so it is answered without ending the session."
                            + " If a legitimate single logout stopped working, compare the NameID the IdP puts in its assertion with the one"
                            + " it puts in its LogoutRequest: {}", sanitizeForLog(outcome.detail(), MAX_LOGGED_FAILURE_REASON_LENGTH));
                }
                if (outcome.action() == LogoutOutcome.Action.END_SESSION) {
                    final HttpSession session = request.getSession(false);
                    if (session != null) {
                        session.invalidate();
                    }
                }
                if (StringUtil.isNotBlank(outcome.redirectUrl())) {
                    // an IdP-initiated LogoutRequest: send our LogoutResponse back to the IdP
                    return HtmlResponse.fromRedirectPathAsIs(outcome.redirectUrl());
                }
                throw new SsoMessageException(messages -> messages.addSuccessSsoLogout(UserMessages.GLOBAL_PROPERTY_KEY), "Logged out");
            } catch (final SsoMessageException e) {
                throw e;
            } catch (final SamlConfigException e) {
                // an anonymous request to a server whose settings are invalid: one line, not a stack trace per request, and
                // no setting names on the login page
                throw processFailure("Failed to log out.", "The SAML settings are invalid.",
                        new SsoStateException(sanitizeForLog(e.getMessage(), MAX_LOGGED_FAILURE_REASON_LENGTH)));
            } catch (final Exception e) {
                throw processFailure("Failed to log out.", e.getMessage(), e);
            }
        }).orElseThrow(() -> processFailure("Failed to log out.", "Invalid state."));
    }

    /**
     * Bounds a value to {@link #MAX_LOGGED_NAME_ID_LENGTH} and strips its control characters so that it can be
     * embedded in a log message.
     *
     * @param value The value to embed in a log message.
     * @return A value safe to embed in a log message.
     */
    protected static String sanitizeForLog(final String value) {
        return sanitizeForLog(value, MAX_LOGGED_NAME_ID_LENGTH);
    }

    /**
     * Bounds a value to {@code maxLength} and strips its control characters so that it can be
     * embedded in a log message.
     *
     * @param value The value to embed in a log message.
     * @param maxLength The number of characters to keep before truncating.
     * @return A value safe to embed in a log message.
     */
    protected static String sanitizeForLog(final String value, final int maxLength) {
        final String text = value == null ? "null" : value;
        final String bounded = text.length() > maxLength ? text.substring(0, maxLength) + "..." : text;
        return LOG_UNSAFE_PATTERN.matcher(bounded).replaceAll("?");
    }

    /**
     * Returns the SAML user of this session, or null when it did not come from SAML.
     *
     * <p>Being unable to look at the session means "cannot tell", not "fail": this endpoint has to keep
     * working for a request that reaches it outside a login scope.</p>
     *
     * @return The SAML user of the session, or null.
     */
    protected SamlUser getSessionSamlUser() {
        try {
            final FessUserBean userBean = getSavedUserBean().orElse(null);
            if (userBean != null && userBean.getFessUser() instanceof final SamlUser samlUser) {
                return samlUser;
            }
        } catch (final Exception e) {
            if (logger.isDebugEnabled()) {
                logger.debug("Failed to read the session user.", e);
            }
        }
        return null;
    }

    /**
     * Returns the user bean held by the session.
     *
     * <p>Separate from {@link #getSessionSamlUser()} so that a test can decide who is logged in
     * without standing up a login scope.</p>
     *
     * @return The user bean of the session, empty when nobody is logged in.
     */
    protected OptionalThing<FessUserBean> getSavedUserBean() {
        return ComponentUtil.getFessLoginAssist().getSavedUserBean();
    }
}
