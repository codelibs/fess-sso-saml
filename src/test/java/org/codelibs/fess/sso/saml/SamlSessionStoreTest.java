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

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.logging.log4j.Level;
import org.codelibs.fess.app.web.base.login.ActionResponseCredential;
import org.codelibs.fess.helper.SystemHelper;
import org.codelibs.fess.mylasta.action.FessUserBean;
import org.codelibs.fess.session.SessionDataSerializer;
import org.codelibs.fess.sso.saml.SamlCredential.SamlUser;
import org.codelibs.fess.unit.LogCapturingAppender;
import org.codelibs.fess.unit.UnitFessTestCase;
import org.codelibs.fess.util.ComponentUtil;
import org.dbflute.utflute.mocklet.MockletHttpServletRequest;
import org.junit.jupiter.api.Test;
import org.lastaflute.web.login.credential.LoginCredential;
import org.objenesis.ObjenesisStd;

import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * What the plugin puts in a session that the OpenSearch-backed session store of Fess shares between nodes.
 */
public class SamlSessionStoreTest extends UnitFessTestCase {

    private static final String SECRET = "assertion-attribute-secret-4711";

    private static final String PERMISSION_MARKER = "permission-marker-4711";

    private final AtomicLong clock = new AtomicLong(1_000_000L);

    @Override
    protected void tearDown(final org.junit.jupiter.api.TestInfo testInfo) throws Exception {
        removeSerializerComponent();
        super.tearDown(testInfo);
    }

    /** ComponentUtil#register keeps the instance in a static map, which would outlive the test. */
    @SuppressWarnings("unchecked")
    private static void removeSerializerComponent() throws Exception {
        final Field field = ComponentUtil.class.getDeclaredField("componentMap");
        field.setAccessible(true);
        ((Map<String, Object>) field.get(null)).remove("sessionDataSerializer");
    }

    private SessionDataSerializer registered() {
        final SessionDataSerializer serializer = new SessionDataSerializer();
        ComponentUtil.register(serializer, "sessionDataSerializer");
        new SamlAuthenticator().registerSessionSerializers();
        return serializer;
    }

    private void registerSystemHelper() {
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

    private static SamlUser samlUser() {
        return new SamlUser("alice@example.com", "idp-session-1", "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress",
                "idp.example.com", "sp.example.com", new String[] { "dev", "ops" }, new String[] { "admin" });
    }

    private static Map<String, Object> attributes(final String name, final Object value) {
        final Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put(name, value);
        return attributes;
    }

    private static boolean contains(final byte[] bytes, final String text) {
        final byte[] needle = text.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i + needle.length <= bytes.length; i++) {
            if (Arrays.equals(Arrays.copyOfRange(bytes, i, i + needle.length), needle)) {
                return true;
            }
        }
        return false;
    }

    // ===================================================================================
    //                                                                        SamlUser
    //                                                                        ========
    @Test
    public void test_userBean_roundTrip() throws Exception {
        registerSystemHelper();
        final SessionDataSerializer serializer = registered();
        final FessUserBean bean = new FessUserBean(samlUser());
        bean.setLoginTime(1234L);

        final Set<String> skipped = new LinkedHashSet<>();
        final byte[] bytes = serializer.toBytes(attributes("bean", bean), skipped);
        final Map<String, Object> restored = serializer.fromBytes(bytes);

        assertTrue(skipped.toString(), skipped.isEmpty());
        final FessUserBean restoredBean = (FessUserBean) restored.get("bean");
        assertEquals(Long.valueOf(1234L), restoredBean.getLoginTime());
        final SamlUser user = (SamlUser) restoredBean.getFessUser();
        assertEquals("alice@example.com", user.getName());
        assertEquals("idp-session-1", user.getSessionIndex());
        assertEquals("urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress", user.getNameIdFormat());
        assertEquals("idp.example.com", user.getNameidNameQualifier());
        assertEquals("sp.example.com", user.getNameidSPNameQualifier());
        assertEquals(List.of("dev", "ops"), Arrays.asList(user.getGroupNames()));
        assertEquals(List.of("admin"), Arrays.asList(user.getRoleNames()));
        assertEquals(List.of("Ualice@example.com", "Gdev", "Gops", "Radmin").stream().sorted().toList(),
                Arrays.stream(user.getPermissions()).sorted().toList());
    }

    @Test
    public void test_user_optionalValuesMayBeNullAndGroupsMayBeEmpty() throws Exception {
        final SessionDataSerializer serializer = registered();
        final SamlUser original = new SamlUser("bob", null, null, null, null, new String[0], null);

        final FessUserBean restored =
                (FessUserBean) serializer.fromBytes(serializer.toBytes(attributes("u", new FessUserBean(original)))).get("u");
        final SamlUser user = (SamlUser) restored.getFessUser();

        assertEquals("bob", user.getName());
        assertNull(user.getSessionIndex());
        assertNull(user.getNameIdFormat());
        assertEquals(0, user.getGroupNames().length);
        assertEquals(0, user.getRoleNames().length);
    }

    @Test
    public void test_permissionsAreNotStoredAndAreDerivedAgain() throws Exception {
        registerSystemHelper();
        final SessionDataSerializer serializer = registered();
        final SamlUser original = samlUser();
        final Field field = SamlUser.class.getDeclaredField("permissions");
        field.setAccessible(true);
        field.set(original, new String[] { PERMISSION_MARKER });
        assertEquals(PERMISSION_MARKER, original.getPermissions()[0]);

        final byte[] bytes = serializer.toBytes(attributes("bean", new FessUserBean(original)));

        assertFalse(contains(bytes, PERMISSION_MARKER));
        final SamlUser restored = (SamlUser) ((FessUserBean) serializer.fromBytes(bytes).get("bean")).getFessUser();
        assertFalse(Arrays.asList(restored.getPermissions()).contains(PERMISSION_MARKER));
        assertTrue(Arrays.asList(restored.getPermissions()).contains("Gdev"));
    }

    @Test
    public void test_credentialIsNeverStored() throws Exception {
        final SessionDataSerializer serializer = registered();
        // an instance without an assertion to read, made without the constructor that needs one
        final SamlCredential credential = new ObjenesisStd().newInstance(SamlCredential.class);
        final Field attributesField = SamlCredential.class.getDeclaredField("attributes");
        attributesField.setAccessible(true);
        attributesField.set(credential, Map.of("password", List.of(SECRET)));
        final Map<String, Object> attributes = attributes("credential", credential);
        attributes.put("locale", java.util.Locale.JAPAN);

        final Set<String> skipped = new LinkedHashSet<>();
        final byte[] bytes = serializer.toBytes(attributes, skipped);

        assertEquals(Set.of("credential"), skipped);
        assertFalse(contains(bytes, SECRET));
        assertEquals(List.of("locale"), List.copyOf(serializer.fromBytes(bytes).keySet()));
    }

    @Test
    public void test_userWithoutNameIdOrWithBlankGroupIsSkipped() throws Exception {
        final SessionDataSerializer serializer = registered();
        final Set<String> skipped = new LinkedHashSet<>();
        final Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("noName", new FessUserBean(new SamlUser(" ", null, null, null, null, new String[0], new String[0])));
        attributes.put("blankGroup", new FessUserBean(new SamlUser("a", null, null, null, null, new String[] { "" }, new String[0])));
        attributes.put("tooLong", new FessUserBean(
                new SamlUser("a", null, null, null, null, new String[] { "g".repeat(SamlUserSerializer.MAX_LENGTH + 1) }, new String[0])));
        attributes.put("ok", new FessUserBean(samlUser()));

        final Map<String, Object> restored = serializer.fromBytes(serializer.toBytes(attributes, skipped));

        assertEquals(Set.of("noName", "blankGroup", "tooLong"), skipped);
        assertEquals(List.of("ok"), List.copyOf(restored.keySet()));
    }

    // ===================================================================================
    //                                                                      Hardening
    //                                                                      =========
    @Test
    public void test_truncatedBytes_neverEscape() throws Exception {
        final SessionDataSerializer serializer = registered();
        final byte[] bytes = serializer.toBytes(attributes("bean", new FessUserBean(samlUser())));

        for (int length = 0; length < bytes.length; length++) {
            final Map<String, Object> restored = serializer.fromBytes(Arrays.copyOf(bytes, length));
            assertTrue("length " + length, restored == null || !restored.containsKey("bean"));
        }
        assertNotNull(serializer.fromBytes(bytes).get("bean"));
    }

    @Test
    public void test_garbageBytes_neverEscape() throws Exception {
        final SessionDataSerializer serializer = registered();
        final byte[] valid = serializer.toBytes(attributes("bean", new FessUserBean(samlUser())));
        final byte[] header = header(serializer);
        final Random random = new Random(4711L);

        for (int i = 0; i < 500; i++) {
            final byte[] garbage = new byte[random.nextInt(200)];
            random.nextBytes(garbage);
            serializer.fromBytes(garbage);
            serializer.fromBytes(concat(header, garbage));
        }
        // every single byte of a valid session damaged in turn, which reaches every length and class id
        for (int i = 0; i < valid.length; i++) {
            final byte[] damaged = valid.clone();
            damaged[i] ^= (byte) 0xff;
            final Map<String, Object> restored = serializer.fromBytes(damaged);
            if (restored != null && restored.get("bean") instanceof final FessUserBean bean) {
                // whatever survives is still a user this plugin could have produced
                final SamlUser user = (SamlUser) bean.getFessUser();
                assertTrue(user.getName() != null && !user.getName().isBlank());
                assertNotNull(user.getGroupNames());
                assertNotNull(user.getRoleNames());
            }
        }
    }

    @Test
    public void test_unregisteredClassId_dropsTheAttribute() throws Exception {
        final SessionDataSerializer serializer = registered();
        final Output value = new Output(64, -1);
        value.writeVarInt(1_000_000, true);
        value.writeString("payload");

        final Map<String, Object> restored = serializer.fromBytes(concat(header(serializer), entries(entry("x", value.toBytes()))));

        assertNotNull(restored);
        assertFalse(restored.containsKey("x"));
    }

    @Test
    public void test_oversizedCounts_areRefusedBeforeAllocating() throws Exception {
        final SessionDataSerializer serializer = registered();
        final byte[] classId = samlUserClassId(serializer);
        for (final int count : new int[] { Integer.MAX_VALUE, 1_000_000_000, SamlUserSerializer.MAX_VALUES + 1, 50 }) {
            final Output payload = new Output(64, -1);
            payload.writeBytes(classId);
            payload.writeString("alice");
            for (int i = 0; i < 4; i++) {
                payload.writeString(null);
            }
            payload.writeVarInt(count, true);
            payload.writeString("only-one-value");
            final byte[] bytes = concat(header(serializer), entries(entry("x", payload.toBytes())));

            final Map<String, Object> restored = serializer.fromBytes(bytes);

            assertNotNull(restored, "count " + count);
            assertFalse("count " + count, restored.containsKey("x"));
        }
    }

    @Test
    public void test_oversizedString_andBlankValues_areRefused() throws Exception {
        final SessionDataSerializer serializer = registered();
        final byte[] classId = samlUserClassId(serializer);
        final String tooLong = "n".repeat(SamlUserSerializer.MAX_LENGTH + 1);
        final String[][] cases = { { tooLong, null }, { "  ", null }, { null, null }, { "alice", "" }, { "alice", " " } };
        for (final String[] c : cases) {
            final Output payload = new Output(64, -1);
            payload.writeBytes(classId);
            payload.writeString(c[0]);
            for (int i = 0; i < 4; i++) {
                payload.writeString(null);
            }
            payload.writeVarInt(c[1] == null ? 0 : 1, true);
            if (c[1] != null) {
                payload.writeString(c[1]);
            }
            payload.writeVarInt(0, true);
            final Map<String, Object> restored = serializer.fromBytes(concat(header(serializer), entries(entry("x", payload.toBytes()))));

            assertNotNull(restored, Arrays.toString(c));
            assertFalse(Arrays.toString(c), restored.containsKey("x"));
        }
    }

    // ===================================================================================
    //                                                                      Handshake
    //                                                                      =========
    @Test
    public void test_requestIdMap_isSharedAsAConcurrentHashMap() throws Exception {
        final SessionDataSerializer serializer = registered();
        final ConcurrentHashMap<String, Long> ids = new ConcurrentHashMap<>();
        ids.put("_id1", 1000L);
        ids.put("_id2", 2000L);

        final Set<String> skipped = new LinkedHashSet<>();
        final Map<String, Object> restored = serializer.fromBytes(serializer.toBytes(attributes("SAML_STATE", ids), skipped));

        assertTrue(skipped.isEmpty());
        assertTrue(restored.get("SAML_STATE") instanceof ConcurrentHashMap);
        assertEquals(ids, restored.get("SAML_STATE"));
    }

    @Test
    public void test_getRequestIdMap_repairsWhatTheStoreReturned() throws Exception {
        registerSystemHelper();
        final SamlAuthenticator authenticator = new SamlAuthenticator();
        final HttpSession session = getMockRequest().getSession();
        final ConcurrentHashMap<Object, Object> stored = new ConcurrentHashMap<>();
        stored.put("_ok", 5L);
        stored.put("_text", "not a time");
        stored.put("_int", 7);
        stored.put(" ", 9L);
        stored.put(42, 9L);
        session.setAttribute("SAML_STATE", stored);

        final Map<String, Long> map = authenticator.getRequestIdMap(session);

        assertEquals(Map.of("_ok", 5L), map);
        assertSame(map, session.getAttribute("SAML_STATE"));
        // a map that needs no repair is the one in the session
        assertSame(map, authenticator.getRequestIdMap(session));
    }

    @Test
    public void test_getRequestIdMap_keepsTheNewestEntriesOnly() throws Exception {
        registerSystemHelper();
        final SamlAuthenticator authenticator = new SamlAuthenticator();
        final HttpSession session = getMockRequest().getSession();
        final ConcurrentHashMap<String, Long> stored = new ConcurrentHashMap<>();
        for (int i = 0; i < 1000; i++) {
            stored.put("_id" + i, (long) i);
        }
        session.setAttribute("SAML_STATE", stored);

        final Map<String, Long> map = authenticator.getRequestIdMap(session);

        assertEquals(SamlAuthenticator.DEFAULT_MAX_REQUEST_IDS, map.size());
        assertTrue(map.containsKey("_id999"));
        assertFalse(map.containsKey("_id0"));
    }

    @Test
    public void test_removeExpiredRequestIds_dropsATimeAheadOfTheClock() throws Exception {
        registerSystemHelper();
        final SamlAuthenticator authenticator = new SamlAuthenticator();
        final Map<String, Long> map = new ConcurrentHashMap<>();
        map.put("_now", clock.get());
        map.put("_ahead", clock.get() + 10_000_000_000L);

        authenticator.removeExpiredRequestIds(map);

        assertEquals(Set.of("_now"), map.keySet());
    }

    @Test
    public void test_consumedRequestId_isGoneOnTheOtherNode_andReplayIsRefused() throws Exception {
        registerSystemHelper();
        final SessionDataSerializer nodeA = registered();
        final SessionDataSerializer nodeB = registered();
        final SamlAuthenticator starter = new SamlAuthenticator();

        // node A starts two logins (two tabs)
        final HttpSession sessionA = getMockRequest().getSession();
        starter.storeRequestIdInSession(sessionA, "_first");
        clock.addAndGet(1000L);
        starter.storeRequestIdInSession(sessionA, "_second");
        final byte[] stored = nodeA.toBytes(attributes("SAML_STATE", sessionA.getAttribute("SAML_STATE")));

        // node B answers the first one. Another request of the session replaced the attribute by a newer
        // copy meanwhile, as the session store does, so the consumed map is a detached one
        final AtomicBoolean processed = new AtomicBoolean();
        final SamlAuthenticator authenticatorB = consuming("_first", processed, true);
        final MockletHttpServletRequest requestB = getMockRequest();
        requestB.setMethod("POST");
        requestB.setParameter("SAMLResponse", "PHNhbWxwOlJlc3BvbnNlIC8+");
        final HttpSession sessionB = requestB.getSession();
        sessionB.setAttribute("SAML_STATE", nodeB.fromBytes(stored).get("SAML_STATE"));

        assertNotNull(authenticatorB.getLoginCredential());
        assertTrue(processed.get());
        final byte[] afterB = nodeB.toBytes(attributes("SAML_STATE", sessionB.getAttribute("SAML_STATE")));

        // the replay of the same response on node A, whose session is brought up to date from the store
        final Map<String, Long> onA = castMap(nodeA.fromBytes(afterB).get("SAML_STATE"));
        assertEquals(Set.of("_second"), onA.keySet());
        final MockletHttpServletRequest replay = getMockRequest();
        replay.setMethod("POST");
        replay.setParameter("SAMLResponse", "PHNhbWxwOlJlc3BvbnNlIC8+");
        replay.getSession().setAttribute("SAML_STATE", onA);
        final SamlAuthenticator refusing = consuming("_first", new AtomicBoolean(), false);
        // processSamlResponse sees only "_second", which the response does not name
        assertNull(refusing.getLoginCredential());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Long> castMap(final Object value) {
        return (Map<String, Long>) value;
    }

    /**
     * An authenticator whose IdP accepts the response only for {@code requestId}; it consumes that ID from the
     * map it is given, the way {@code processSamlResponse} does, and returns a credential.
     */
    private SamlAuthenticator consuming(final String requestId, final AtomicBoolean processed, final boolean detach) {
        return new SamlAuthenticator() {
            @Override
            protected LoginCredential processSamlResponse(final HttpServletRequest request, final HttpServletResponse response,
                    final Map<String, Long> requestIdMap) {
                if (!requestIdMap.containsKey(requestId)) {
                    return null;
                }
                if (detach) {
                    request.getSession().setAttribute("SAML_STATE", new ConcurrentHashMap<>(requestIdMap));
                }
                requestIdMap.remove(requestId);
                processed.set(true);
                return new ActionResponseCredential(() -> null);
            }
        };
    }

    // ===================================================================================
    //                                                                    Registration
    //                                                                    ============
    @Test
    public void test_register_withoutTheSerializerComponentIsHarmless() throws Exception {
        // an older Fess has no such component
        removeSerializerComponent();
        assertFalse(ComponentUtil.hasComponent("sessionDataSerializer"));

        new SamlAuthenticator().registerSessionSerializers();
    }

    @Test
    public void test_register_afterTheRegistrationsAreFixed_warnsAndDoesNotThrow() throws Exception {
        final SessionDataSerializer serializer = new SessionDataSerializer();
        ComponentUtil.register(serializer, "sessionDataSerializer");
        serializer.getFormatVersion();
        final LogCapturingAppender appender = LogCapturingAppender.attach(SamlAuthenticator.class);
        try {
            new SamlAuthenticator().registerSessionSerializers();

            assertEquals(1, appender.eventsAt(Level.WARN).size(), String.valueOf(appender.warnings()));
        } finally {
            appender.detach();
        }
        // the user is then not shared, as the warning says
        final Set<String> skipped = new LinkedHashSet<>();
        serializer.toBytes(attributes("bean", new FessUserBean(samlUser())), skipped);
        assertEquals(Set.of("bean"), skipped);
    }

    @Test
    public void test_register_twice_warnsAndDoesNotThrow() throws Exception {
        final SessionDataSerializer serializer = registered();
        new SamlAuthenticator().registerSessionSerializers();
        assertNotNull(serializer.getFormatVersion());
    }

    @Test
    public void test_formatVersion_dependsOnThePlugin() throws Exception {
        final String with = registered().getFormatVersion();
        final String without = new SessionDataSerializer().getFormatVersion();
        assertFalse(with.equals(without));
    }

    // ===================================================================================
    //                                                                          Helper
    //                                                                          ======
    private static byte[] header(final SessionDataSerializer serializer) {
        final byte[] empty = serializer.toBytes(Map.of());
        // the format number and the fingerprint, without the count of the entries
        return Arrays.copyOf(empty, empty.length - 1);
    }

    private static byte[] entry(final String name, final byte[] value) {
        final Output output = new Output(64, -1);
        output.writeString(name);
        output.writeVarInt(value.length, true);
        output.writeBytes(value);
        return output.toBytes();
    }

    private static byte[] entries(final byte[]... entries) {
        final Output output = new Output(64, -1);
        output.writeVarInt(entries.length, true);
        for (final byte[] entry : entries) {
            output.writeBytes(entry);
        }
        return output.toBytes();
    }

    private static byte[] concat(final byte[] first, final byte[] second) {
        final byte[] all = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, all, first.length, second.length);
        return all;
    }

    /** The class id that the serializer writes in front of a {@link SamlUser}. */
    private static byte[] samlUserClassId(final SessionDataSerializer serializer) {
        final Input input = new Input(serializer.toBytes(attributes("u", samlUser())));
        input.readVarInt(true);
        input.readLong();
        input.readVarInt(true);
        input.readString();
        final byte[] value = input.readBytes(input.readVarInt(true));
        final Input valueInput = new Input(value);
        valueInput.readVarInt(true);
        return Arrays.copyOf(value, valueInput.position());
    }
}
