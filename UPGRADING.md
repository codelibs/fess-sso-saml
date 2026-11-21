# Upgrading

## 15.10

The plugin uses [saml4j](https://github.com/codelibs/saml4j) instead of java-saml. The `saml.*` properties keep
their names, and the endpoints and the stored user are unchanged. Two things about sessions are new, and are
described under [Sessions](#sessions) below.

### Properties that are no longer used

These are ignored, with one warning in the log that names them:

| Property | Now |
| --- | --- |
| `saml.security.reject_deprecated_alg` | SHA-1 signatures are rejected by default; `saml.security.allow_deprecated_alg=true` accepts them |
| `saml.security.allowed_key_transport_algorithms` | only OAEP is accepted by default; `saml.security.allow_rsa_1_5=true` accepts RSA 1.5 as well |
| `saml.security.allow_duplicated_attribute_name` | repeated attributes are always merged |
| `saml.security.reject_missing_audience` | an assertion with no audience is always rejected |
| `saml.idp.certfingerprint`, `saml.idp.certfingerprint_algorithm` | set `saml.idp.x509cert`; a fingerprint is no longer a trust anchor |
| `saml.security.sign_metadata`, `saml.security.want_nameid_encrypted`, `saml.security.want_xml_validation`, `keystore.*`, `contacts.*`, `organization.*`, `compress.*`, `parsing.*`, `unique_id_prefix`, the `*.binding` and `*.response.url` properties | no longer used |

Any other `saml.` property that the library does not know stops SAML logins with a message that names it, so that a
mistyped security setting cannot go unnoticed.

### Sessions

* **The login ends with the IdP session.** With `saml.session.end_with_idp` (default `true`), a login ends at the
  `SessionNotOnOrAfter` of the assertion plus `saml.security.clock_drift`, instead of lasting as long as the Fess
  session. An IdP that sets a short session, such as Keycloak with its default of 10 hours, therefore logs users out
  earlier than before. Set `saml.session.end_with_idp=false` to keep the previous behaviour.
* **The login can be shared between nodes.** With `FESS_SESSION_STORE=opensearch` a login can start on one node and
  finish on another, and the logged-in user is shared; without it SAML still needs sticky sessions. This needs plugin
  15.10 on every node. Adding or removing an SSO plugin changes what the stored sessions contain, so it invalidates
  them: users log in again.

### Behaviour that changed

* **Signed logout messages.** With `saml.idp.single_logout_service.url` set, the IdP's LogoutRequest and
  LogoutResponse must be signed by `saml.idp.x509cert`. Set `saml.security.want_logout_signed=false` only for an IdP that
  cannot sign them.
* **Audience.** The assertion must carry an `AudienceRestriction` that names the SP entity ID.
* **Destination.** A signed Response must carry a `Destination` that is the assertion consumer service URL, and the
  SubjectConfirmation `Recipient` must be that URL. The URLs come from `saml.sp.base.url`, not from the request.
* **SHA-1 and RSA 1.5** are refused unless the two properties above are set.
* **One trust anchor.** The IdP certificate (or `saml.idp.x509certMulti.N`) is the only thing that can sign; the
  certificate inside the message is never trusted.
* **Logout bindings.** The single logout service takes the redirect binding (GET) and the POST binding, which is what
  Keycloak uses unless the client sets `saml.force.post.binding` off; a POST binding message carries an XML signature.
  A LogoutResponse that an IdP posts to the assertion consumer service instead is not recognised: give the IdP client the
  `/sso/logout` URL for the POST binding as well.
* **Strict mode only.** `saml.strict=false` is refused.
* **Signature shape.** A signature must reference the signed element by its own ID (`Reference URI=""` is refused), use
  one of `rsa-sha256`, `rsa-sha384`, `rsa-sha512` (or the ECDSA variants), and the outgoing signature algorithm
  `saml.security.signature_algorithm` is one of the three RSA ones.
* **Attributes.** An `AttributeValue` that holds child elements instead of text is skipped.
* **Control characters in the NameID.** The NameID is the user name and is kept exactly as the IdP sent it, so a
  NameID that contains a control character (a line break, a TAB, `U+0085`, and the like, or `U+2028` / `U+2029`) is
  not rewritten: the login is refused, with one warning that names the character and its position and not the value.
  Spaces, letters of any script, `@`, `+` and `'` are accepted as before.
* **Time.** An assertion whose `IssueInstant` is more than the clock drift in the future is refused.
* **Logout of a session that did not come from SAML.** A LogoutRequest from the IdP never ends a local or admin
  session; it ends the SAML session it names.
