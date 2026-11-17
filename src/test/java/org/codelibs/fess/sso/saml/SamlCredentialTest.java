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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.codelibs.core.misc.DynamicProperties;
import org.codelibs.fess.sso.saml.SamlCredential.SamlUser;
import org.codelibs.fess.util.ComponentUtil;
import org.codelibs.saml4j.LoginResult;
import org.codelibs.saml4j.NameId;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SamlCredentialTest extends SamlTestCase {

    private static LoginResult.Authenticated login(final String nameId, final Map<String, List<String>> attributes) {
        return new LoginResult.Authenticated(
                new NameId(nameId, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", "idp.example.com", "fess.example.com"),
                "_session1", null, attributes, "_request1");
    }

    private static Map<String, List<String>> attributes(final String name, final String... values) {
        final Map<String, List<String>> attributes = new LinkedHashMap<>();
        attributes.put(name, List.of(values));
        return attributes;
    }

    @Test
    public void test_credential_takesTheUserFromTheLogin() throws Exception {
        final SamlCredential credential = new SamlCredential(login(USER, Map.of()));

        assertEquals(USER, credential.getUserId());
        final SamlUser user = credential.getUser();
        assertEquals(USER, user.getName());
        assertEquals("_session1", user.getSessionIndex());
        assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", user.getNameIdFormat());
        assertEquals("idp.example.com", user.getNameidNameQualifier());
        assertEquals("fess.example.com", user.getNameidSPNameQualifier());
        Assertions.assertArrayEquals(new String[0], user.getGroupNames());
        Assertions.assertArrayEquals(new String[0], user.getRoleNames());
    }

    @Test
    public void test_credential_groupsComeFromMemberOfUnlessAnotherAttributeIsNamed() throws Exception {
        final Map<String, List<String>> attributes = new LinkedHashMap<>();
        attributes.put("memberOf", List.of("staff", "dev"));
        attributes.put("groups", List.of("other"));

        Assertions.assertArrayEquals(new String[] { "staff", "dev" },
                new SamlCredential(login(USER, attributes)).getUser().getGroupNames());

        ComponentUtil.getSystemProperties().setProperty("saml.attribute.group.name", "groups");

        Assertions.assertArrayEquals(new String[] { "other" }, new SamlCredential(login(USER, attributes)).getUser().getGroupNames());
    }

    @Test
    public void test_credential_rolesComeFromTheNamedAttributeAndTheDefaults() throws Exception {
        final DynamicProperties systemProperties = ComponentUtil.getSystemProperties();
        final Map<String, List<String>> attributes = attributes("roles", "r1", "r2");

        // no attribute is named, so the attribute is not read
        Assertions.assertArrayEquals(new String[0], new SamlCredential(login(USER, attributes)).getUser().getRoleNames());

        systemProperties.setProperty("saml.attribute.role.name", "roles");
        systemProperties.setProperty("saml.default.roles", "viewer");

        Assertions.assertArrayEquals(new String[] { "r1", "r2", "viewer" },
                new SamlCredential(login(USER, attributes)).getUser().getRoleNames());
    }

    @Test
    public void test_credential_dropsBlankValuesAndTrimsTheDefaults() throws Exception {
        final DynamicProperties systemProperties = ComponentUtil.getSystemProperties();
        systemProperties.setProperty("saml.default.groups", " a , ,b ");

        final SamlUser user = new SamlCredential(login(USER, attributes("memberOf", "", " ", "staff"))).getUser();

        Assertions.assertArrayEquals(new String[] { "staff", "a", "b" }, user.getGroupNames());
    }

    @Test
    public void test_credentialToString_keepsTheUserOnOneLineAndLeavesTheAttributesOut() throws Exception {
        final SamlCredential credential = new SamlCredential(
                login("alice\n2099-01-01 00:00:00,000 [forged] ERROR FORGED", attributes("secret", "attribute-secret-4711")));

        final String text = credential.toString();

        assertFalse(text, text.contains("\r") || text.contains("\n"));
        assertTrue(text, text.contains("alice?2099"));
        assertFalse(text, text.contains("attribute-secret-4711"));
    }

    @Test
    public void test_samlUserToString_keepsIdentityProviderValuesOnOneLine() throws Exception {
        // the string form is what the debug log prints for a logged-in user, and a group name is
        // whatever the identity provider released
        final String forged = "evil\r\n2026-01-01 00:00:00,000 [main] ERROR  FORGED";
        final SamlUser user = new SamlUser("name\nid", "_sessionIndex", null, null, null, new String[] { forged }, new String[] { "r\ro" });
        final String text = user.toString();
        assertFalse(text, text.contains("\r") || text.contains("\n"));
        assertTrue(text, text.contains("FORGED"));
        assertTrue(text, text.contains("name?id"));
    }

    @Test
    public void test_samlUser_permissionsAreDerivedFromTheNameIdTheGroupsAndTheRoles() throws Exception {
        registerSystemHelper();
        final SamlUser user = new SamlUser(USER, "_session1", null, null, null, new String[] { "dev" }, new String[] { "admin" });

        Assertions.assertEquals(java.util.Set.of("U" + USER, "Gdev", "Radmin"), java.util.Set.of(user.getPermissions()));
        assertSame(user.getPermissions(), user.getPermissions());
    }
}
