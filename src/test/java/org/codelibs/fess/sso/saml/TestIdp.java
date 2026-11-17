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

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.Deflater;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * An identity provider for tests: it builds SAML responses and logout messages, signs and encrypts them, and lets a
 * test change the document before it is encoded.
 */
public final class TestIdp {

    public static final String IDP = "https://idp.example.com/metadata";

    public static final String SSO = "https://idp.example.com/sso";

    public static final String SLO = "https://idp.example.com/slo";

    public static final String SP = "https://fess.example.com/sso/metadata";

    public static final String ACS = "https://fess.example.com/sso/";

    public static final String SLS = "https://fess.example.com/sso/logout";

    public static final Instant NOW = Instant.parse("2026-11-17T09:00:00Z");

    public static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    public static final PrivateKey IDP_KEY = key("idp");

    public static final X509Certificate IDP_CERT = cert("idp");

    public static final PrivateKey SP_KEY = key("sp");

    public static final X509Certificate SP_CERT = cert("sp");

    public static final PrivateKey OTHER_KEY = key("other");

    public static final X509Certificate OTHER_CERT = cert("other");

    private static final AtomicInteger COUNTER = new AtomicInteger();

    static {
        org.apache.xml.security.Init.init();
    }

    private TestIdp() {
    }

    /** The names the messages are built from, kept here so that the tests do not depend on the library's internals. */
    private static final class Names {
        static final String NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
        static final String NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
        static final String NS_DS = "http://www.w3.org/2000/09/xmldsig#";
        static final String NS_XENC = "http://www.w3.org/2001/04/xmlenc#";
        static final String STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
        static final String CM_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
        static final String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        static final String SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
        static final String KEY_TRANSPORT_RSA15 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
    }

    private static final class Text {
        static String xml(final String value) {
            final StringBuilder sb = new StringBuilder(value.length() + 16);
            for (int i = 0; i < value.length(); i++) {
                final char c = value.charAt(i);
                switch (c) {
                case '&':
                    sb.append("&amp;");
                    break;
                case '<':
                    sb.append("&lt;");
                    break;
                case '>':
                    sb.append("&gt;");
                    break;
                case '"':
                    sb.append("&quot;");
                    break;
                case '\'':
                    sb.append("&apos;");
                    break;
                case '\t':
                case '\n':
                case '\r':
                    sb.append("&#").append((int) c).append(';');
                    break;
                default:
                    if (c < 0x20 || c == 0x7f) {
                        sb.append('?');
                    } else {
                        sb.append(c);
                    }
                }
            }
            return sb.toString();
        }

        static String urlEncode(final String value) {
            final byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            final StringBuilder sb = new StringBuilder(bytes.length + 16);
            for (final byte b : bytes) {
                final int c = b & 0xff;
                if (c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~') {
                    sb.append((char) c);
                } else {
                    sb.append('%')
                            .append(Character.toUpperCase(Character.forDigit(c >> 4, 16)))
                            .append(Character.toUpperCase(Character.forDigit(c & 0xf, 16)));
                }
            }
            return sb.toString();
        }
    }

    private static String read(final String name) {
        try {
            try (java.io.InputStream in = TestIdp.class.getResourceAsStream("/keys/" + name)) {
                return new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static PrivateKey key(final String name) {
        return parseKey(read(name + "-pkcs8.pem"));
    }

    private static PrivateKey parseKey(final String pem) {
        try {
            final String body = pem.replaceAll("-----(BEGIN|END) PRIVATE KEY-----", "").replaceAll("\\s", "");
            return java.security.KeyFactory.getInstance("RSA")
                    .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static X509Certificate cert(final String name) {
        try {
            return (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(read(name + ".crt").getBytes(StandardCharsets.UTF_8)));
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String pem(final String name) {
        return read(name + ".crt");
    }

    public static String keyPem(final String name) {
        return read(name + "-pkcs8.pem");
    }

    // ---- responses -------------------------------------------------------------------------------------------------

    /** What goes into a response. Every field can be changed by a test. */
    public static final class ResponseSpec {

        public String requestId = "_req1";

        public String destination = ACS;

        public String recipient = ACS;

        public String audience = SP;

        public String issuer = IDP;

        public String nameId = "alice@example.com";

        public String nameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

        public Map<String, List<String>> attributes = new LinkedHashMap<>(Map.of("memberOf", List.of("staff", "dev")));

        public String sessionIndex = "_session1";

        public Instant sessionNotOnOrAfter;

        public Instant issueInstant = NOW;

        public Instant notBefore = NOW.minusSeconds(60);

        public Instant notOnOrAfter = NOW.plusSeconds(300);

        public Instant confirmationNotOnOrAfter = NOW.plusSeconds(300);

        public String status = Names.STATUS_SUCCESS;

        public boolean signResponse = true;

        public boolean signAssertion = false;

        public String sigAlg = Names.RSA_SHA256;

        public String digestAlg = "http://www.w3.org/2001/04/xmlenc#sha256";

        public PrivateKey signKey = IDP_KEY;

        public String encryption; // null, "cbc", "gcm"

        public String keyTransport = "oaep"; // "oaep" or "rsa15"

        public String assertionId = "_assertion" + COUNTER.incrementAndGet();

        public String responseId = "_response" + COUNTER.incrementAndGet();

        /** Builds the document. */
        public Document document() {
            return TestIdp.document(this);
        }

        /** Builds, and encodes as the {@code SAMLResponse} parameter. */
        public String encoded() {
            return TestIdp.encode(document());
        }
    }

    public static ResponseSpec response() {
        return new ResponseSpec();
    }

    private static String assertionXml(final ResponseSpec s) {
        final StringBuilder sb = new StringBuilder();
        sb.append("<saml:Assertion xmlns:saml=\"")
                .append(Names.NS_SAML)
                .append("\" ID=\"")
                .append(s.assertionId)
                .append("\" Version=\"2.0\" IssueInstant=\"")
                .append(s.issueInstant)
                .append("\">");
        sb.append("<saml:Issuer>").append(Text.xml(s.issuer)).append("</saml:Issuer>");
        sb.append("<saml:Subject><saml:NameID Format=\"")
                .append(Text.xml(s.nameIdFormat))
                .append("\">")
                .append(Text.xml(s.nameId))
                .append("</saml:NameID><saml:SubjectConfirmation Method=\"")
                .append(Names.CM_BEARER)
                .append("\"><saml:SubjectConfirmationData NotOnOrAfter=\"")
                .append(s.confirmationNotOnOrAfter)
                .append("\" Recipient=\"")
                .append(Text.xml(s.recipient))
                .append("\" InResponseTo=\"")
                .append(Text.xml(s.requestId))
                .append("\"/></saml:SubjectConfirmation></saml:Subject>");
        sb.append("<saml:Conditions NotBefore=\"")
                .append(s.notBefore)
                .append("\" NotOnOrAfter=\"")
                .append(s.notOnOrAfter)
                .append("\"><saml:AudienceRestriction><saml:Audience>")
                .append(Text.xml(s.audience))
                .append("</saml:Audience></saml:AudienceRestriction></saml:Conditions>");
        sb.append("<saml:AuthnStatement AuthnInstant=\"").append(NOW).append('"');
        if (s.sessionIndex != null) {
            sb.append(" SessionIndex=\"").append(Text.xml(s.sessionIndex)).append('"');
        }
        if (s.sessionNotOnOrAfter != null) {
            sb.append(" SessionNotOnOrAfter=\"").append(s.sessionNotOnOrAfter).append('"');
        }
        sb.append("><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password")
                .append("</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>");
        if (!s.attributes.isEmpty()) {
            sb.append("<saml:AttributeStatement>");
            for (final Map.Entry<String, List<String>> e : s.attributes.entrySet()) {
                sb.append("<saml:Attribute Name=\"").append(Text.xml(e.getKey())).append("\">");
                for (final String v : e.getValue()) {
                    sb.append("<saml:AttributeValue>").append(Text.xml(v)).append("</saml:AttributeValue>");
                }
                sb.append("</saml:Attribute>");
            }
            sb.append("</saml:AttributeStatement>");
        }
        return sb.append("</saml:Assertion>").toString();
    }

    private static Document document(final ResponseSpec s) {
        final String xml = "<samlp:Response xmlns:samlp=\"" + Names.NS_SAMLP + "\" xmlns:saml=\"" + Names.NS_SAML + "\" ID=\""
                + s.responseId + "\" Version=\"2.0\" IssueInstant=\"" + NOW + "\" Destination=\"" + Text.xml(s.destination)
                + "\" InResponseTo=\"" + Text.xml(s.requestId) + "\"><saml:Issuer>" + Text.xml(s.issuer)
                + "</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"" + s.status + "\"/></samlp:Status></samlp:Response>";
        final Document doc = parse(xml);
        final Element response = doc.getDocumentElement();
        final Element assertion = parse(assertionXml(s)).getDocumentElement();
        final Element imported = (Element) doc.importNode(assertion, true);
        response.appendChild(imported);
        imported.setIdAttributeNS(null, "ID", true);
        if (s.signAssertion) {
            sign(imported, s.signKey, s.sigAlg, s.digestAlg);
        }
        if (s.encryption != null) {
            // as an IdP does: the assertion is serialized without the declarations its parent carries
            final String plain = serialize(imported).replaceFirst(" xmlns:saml=\"[^\"]*\"", "");
            response.removeChild(imported);
            final Element enc = (Element) doc.importNode(parse(encryptedAssertion(plain, s)).getDocumentElement(), true);
            response.appendChild(enc);
        }
        response.setIdAttributeNS(null, "ID", true);
        if (s.signResponse) {
            sign(response, s.signKey, s.sigAlg, s.digestAlg);
        }
        return doc;
    }

    /** Signs an element, placing the signature after its Issuer. */
    public static void sign(final Element element, final PrivateKey key, final String sigAlg, final String digestAlg) {
        try {
            final Document doc = element.getOwnerDocument();
            element.setIdAttributeNS(null, "ID", true);
            final XMLSignature sig = new XMLSignature(doc, "", sigAlg, "http://www.w3.org/2001/10/xml-exc-c14n#");
            final Node after = element.getFirstChild().getNextSibling();
            element.insertBefore(sig.getElement(), after);
            final Transforms t = new Transforms(doc);
            t.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
            t.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
            sig.addDocument("#" + element.getAttribute("ID"), t, digestAlg);
            sig.sign(key);
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String encryptedAssertion(final String plain, final ResponseSpec s) {
        try {
            final SecureRandom random = new SecureRandom();
            final byte[] aes = new byte[16];
            random.nextBytes(aes);
            final byte[] data;
            final String dataAlg;
            if ("gcm".equals(s.encryption)) {
                final byte[] iv = new byte[12];
                random.nextBytes(iv);
                final Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aes, "AES"), new GCMParameterSpec(128, iv));
                data = concat(iv, c.doFinal(plain.getBytes(StandardCharsets.UTF_8)));
                dataAlg = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
            } else {
                final byte[] iv = new byte[16];
                random.nextBytes(iv);
                final Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aes, "AES"), new IvParameterSpec(iv));
                data = concat(iv, c.doFinal(plain.getBytes(StandardCharsets.UTF_8)));
                dataAlg = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
            }
            final String keyAlg;
            final Cipher kc;
            if ("rsa15".equals(s.keyTransport)) {
                kc = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                keyAlg = "<xenc:EncryptionMethod Algorithm=\"" + Names.KEY_TRANSPORT_RSA15 + "\"/>";
            } else {
                kc = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
                keyAlg = "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\">"
                        + "<ds:DigestMethod Algorithm=\"" + Names.SHA1 + "\"/></xenc:EncryptionMethod>";
            }
            kc.init(Cipher.ENCRYPT_MODE, SP_CERT.getPublicKey());
            final String wrapped = Base64.getEncoder().encodeToString(kc.doFinal(aes));
            return encryptedAssertionXml(dataAlg, keyAlg, wrapped, Base64.getEncoder().encodeToString(data));
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** The EncryptedAssertion element, from its parts; tests use it to build variants. */
    public static String encryptedAssertionXml(final String dataAlg, final String keyMethodXml, final String wrappedKey,
            final String cipherValue) {
        return "<saml:EncryptedAssertion xmlns:saml=\"" + Names.NS_SAML + "\" xmlns:xenc=\"" + Names.NS_XENC + "\" xmlns:ds=\""
                + Names.NS_DS
                + "\"><xenc:EncryptedData Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><xenc:EncryptionMethod Algorithm=\"" + dataAlg
                + "\"/><ds:KeyInfo><xenc:EncryptedKey>" + keyMethodXml + "<xenc:CipherData><xenc:CipherValue>" + wrappedKey
                + "</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>" + cipherValue
                + "</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>";
    }

    private static byte[] concat(final byte[] a, final byte[] b) {
        final byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    // ---- logout messages -------------------------------------------------------------------------------------------

    /** Builds a LogoutRequest from the IdP. */
    public static String logoutRequestXml(final String id, final String nameId, final String sessionIndex) {
        return "<samlp:LogoutRequest xmlns:samlp=\"" + Names.NS_SAMLP + "\" xmlns:saml=\"" + Names.NS_SAML + "\" ID=\"" + id
                + "\" Version=\"2.0\" IssueInstant=\"" + NOW + "\" Destination=\"" + SLS + "\"><saml:Issuer>" + IDP
                + "</saml:Issuer><saml:NameID>" + Text.xml(nameId) + "</saml:NameID>"
                + (sessionIndex == null ? "" : "<samlp:SessionIndex>" + Text.xml(sessionIndex) + "</samlp:SessionIndex>")
                + "</samlp:LogoutRequest>";
    }

    /** Builds a LogoutResponse from the IdP. */
    public static String logoutResponseXml(final String id, final String status) {
        return "<samlp:LogoutResponse xmlns:samlp=\"" + Names.NS_SAMLP + "\" xmlns:saml=\"" + Names.NS_SAML + "\" ID=\"" + id
                + "\" Version=\"2.0\" IssueInstant=\"" + NOW + "\" Destination=\"" + SLS + "\" InResponseTo=\"_lr1\"><saml:Issuer>" + IDP
                + "</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"" + status + "\"/></samlp:Status></samlp:LogoutResponse>";
    }

    /**
     * Builds the query string of a redirect-binding message, signed with the given key (or unsigned if the key is
     * {@code null}).
     */
    public static String redirectQuery(final String param, final String xml, final String relayState, final PrivateKey key) {
        final StringBuilder q = new StringBuilder(param).append('=').append(Text.urlEncode(deflate(xml)));
        if (relayState != null) {
            q.append("&RelayState=").append(Text.urlEncode(relayState));
        }
        if (key != null) {
            q.append("&SigAlg=").append(Text.urlEncode(Names.RSA_SHA256));
            final String signature = rsaSign(q.toString(), key, "SHA256withRSA");
            q.append("&Signature=").append(Text.urlEncode(signature));
        }
        return q.toString();
    }

    public static String rsaSign(final String data, final PrivateKey key, final String jca) {
        try {
            final Signature s = Signature.getInstance(jca);
            s.initSign(key);
            s.update(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(s.sign());
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String deflate(final String xml) {
        final Deflater d = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        d.setInput(xml.getBytes(StandardCharsets.UTF_8));
        d.finish();
        final java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        final byte[] buf = new byte[4096];
        while (!d.finished()) {
            out.write(buf, 0, d.deflate(buf));
        }
        d.end();
        return Base64.getEncoder().encodeToString(out.toByteArray());
    }

    // ---- document helpers ------------------------------------------------------------------------------------------

    public static Document parse(final String xml) {
        try {
            final DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setNamespaceAware(true);
            return f.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String serialize(final Node node) {
        try {
            final Transformer t = TransformerFactory.newInstance().newTransformer();
            t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            final StringWriter w = new StringWriter();
            t.transform(new DOMSource(node), new StreamResult(w));
            return w.toString();
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Encodes a document as a {@code SAMLResponse} POST parameter. */
    public static String encode(final Document doc) {
        return Base64.getEncoder().encodeToString(serialize(doc).getBytes(StandardCharsets.UTF_8));
    }

    /** Encodes XML text as a {@code SAMLResponse} POST parameter. */
    public static String encode(final String xml) {
        return Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
    }

    public static List<Element> all(final Document doc, final String ns, final String local) {
        final List<Element> list = new ArrayList<>();
        final org.w3c.dom.NodeList nl = doc.getElementsByTagNameNS(ns, local);
        for (int i = 0; i < nl.getLength(); i++) {
            list.add((Element) nl.item(i));
        }
        return list;
    }

    public static Instant now() {
        return NOW.truncatedTo(ChronoUnit.SECONDS);
    }
}
