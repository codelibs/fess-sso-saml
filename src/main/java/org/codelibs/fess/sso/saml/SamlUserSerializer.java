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

import org.codelibs.core.lang.StringUtil;
import org.codelibs.fess.sso.saml.SamlCredential.SamlUser;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.KryoException;
import com.esotericsoftware.kryo.Serializer;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;

/**
 * Writes a {@link SamlUser} for the OpenSearch-backed session store of Fess, so that a login through SAML
 * survives a request that another node answers.
 *
 * <p>What is written is what the code of this plugin and the session checks of Fess read from a logged-in
 * user: the NameID (the user name, and what {@link SamlAuthenticator#getSessionSamlNameId()} compares a
 * LogoutRequest with), the groups and the roles (the input of the permissions), and the four values of
 * {@link SamlAuthenticator#logout} that address the session at the IdP (the session index, the NameID format
 * and the two qualifiers).</p>
 *
 * <p>Not written: the permissions. They are a cache that {@link SamlUser#getPermissions()} derives from the
 * NameID, the groups and the roles, so the node that reads the user computes them with its own
 * configuration, and nothing stored can add a permission directly. The assertion and the attributes of the
 * {@link SamlCredential} are not written either: the credential is never a session attribute, and it is not
 * registered, so it is skipped if it ever is one.</p>
 *
 * <p>What is read is checked: a value that the login of this plugin could not have produced makes the read
 * fail, which the store treats as an attribute that does not exist, so the node asks for a new login. The
 * number and the length of the values are bounded before anything is allocated.</p>
 */
public class SamlUserSerializer extends Serializer<SamlUser> {

    /** The most groups, or roles, that are written or read. */
    protected static final int MAX_VALUES = 10_000;

    /** The longest NameID, group, role or other string that is written or read. */
    protected static final int MAX_LENGTH = 4096;

    /**
     * Creates the serializer.
     */
    public SamlUserSerializer() {
        // nothing to do
    }

    @Override
    public void write(final Kryo kryo, final Output output, final SamlUser user) {
        if (StringUtil.isBlank(user.getName())) {
            throw new KryoException("The SAML user has no NameID.");
        }
        writeString(output, user.getName());
        writeString(output, user.getSessionIndex());
        writeString(output, user.getNameIdFormat());
        writeString(output, user.getNameidNameQualifier());
        writeString(output, user.getNameidSPNameQualifier());
        writeValues(output, user.getGroupNames());
        writeValues(output, user.getRoleNames());
    }

    @Override
    public SamlUser read(final Kryo kryo, final Input input, final Class<? extends SamlUser> type) {
        final String nameId = readString(input);
        if (StringUtil.isBlank(nameId)) {
            throw new KryoException("The stored SAML user has no NameID.");
        }
        final String sessionIndex = readString(input);
        final String nameIdFormat = readString(input);
        final String nameQualifier = readString(input);
        final String spNameQualifier = readString(input);
        final String[] groups = readValues(input);
        final String[] roles = readValues(input);
        return new SamlUser(nameId, sessionIndex, nameIdFormat, nameQualifier, spNameQualifier, groups, roles);
    }

    private static void writeString(final Output output, final String value) {
        if (value != null && value.length() > MAX_LENGTH) {
            throw new KryoException("A value of the SAML user is longer than " + MAX_LENGTH + " characters.");
        }
        output.writeString(value);
    }

    private static String readString(final Input input) {
        final String value = input.readString();
        if (value != null && value.length() > MAX_LENGTH) {
            throw new KryoException("A stored value of the SAML user is longer than " + MAX_LENGTH + " characters.");
        }
        return value;
    }

    private static void writeValues(final Output output, final String[] values) {
        final int length = values == null ? 0 : values.length;
        if (length > MAX_VALUES) {
            throw new KryoException("The SAML user has more than " + MAX_VALUES + " groups or roles.");
        }
        output.writeVarInt(length, true);
        for (int i = 0; i < length; i++) {
            if (StringUtil.isBlank(values[i])) {
                throw new KryoException("The SAML user has a blank group or role.");
            }
            writeString(output, values[i]);
        }
    }

    private static String[] readValues(final Input input) {
        final int length = input.readVarInt(true);
        // checked before the array is allocated
        if (length < 0 || length > MAX_VALUES) {
            throw new KryoException("The stored SAML user has an invalid number of groups or roles: " + length);
        }
        final String[] values = new String[length];
        for (int i = 0; i < length; i++) {
            values[i] = readString(input);
            if (StringUtil.isBlank(values[i])) {
                throw new KryoException("The stored SAML user has a blank group or role.");
            }
        }
        return values;
    }
}
