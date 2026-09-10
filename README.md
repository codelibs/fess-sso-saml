SAML SSO Plugin for Fess
[![Java CI with Maven](https://github.com/codelibs/fess-sso-saml/actions/workflows/maven.yml/badge.svg)](https://github.com/codelibs/fess-sso-saml/actions/workflows/maven.yml)
========================

SAML 2.0 single sign-on support for [Fess](https://github.com/codelibs/fess).

This plugin provides the **authenticator** behind `sso.type=saml`, which is what makes Fess act as a
SAML service provider. It answers the three endpoints `SsoAction` routes to it:

* `/sso/` starts the login by redirecting to the IdP, and is also the assertion consumer service the
  IdP posts the assertion back to
* `/sso/metadata` publishes the SP metadata, which is what the IdP is registered from
* `/sso/logout` is the single logout service

It was part of the Fess distribution until 15.9. It moved here with java-saml and Apache Santuario,
1.3 MiB of jars that an installation authenticating any other way never loads.

Only SP-initiated login is supported. Every SAML response is bound to the ID of the AuthnRequest
Fess sent, so an unsolicited (IdP-initiated) response has nothing to match against and is refused;
point an IdP-side tile at `/sso/` instead.

## Installation

```
$ bin/fess-setup install plugin fess-sso-saml
```

Or download the jar from [maven.codelibs.org](https://maven.codelibs.org/org/codelibs/fess/fess-sso-saml/)
and put it in `app/WEB-INF/plugin`. Restart Fess afterwards: the components this plugin
contributes are read when the DI container is built.

## Configuration

Set these in the admin general page, or write them into `app/WEB-INF/conf/system.properties`, which
is the file that page saves to. Not `fess_config.properties`.

| Key | Value |
| --- | --- |
| `sso.type` | `saml` |
| `saml.idp.entityid` | the IdP entity ID |
| `saml.idp.single_sign_on_service.url` | where the AuthnRequest is sent |
| `saml.idp.single_logout_service.url` | the IdP single logout service (leave blank to not use SLO) |
| `saml.idp.x509cert` | the IdP signing certificate, base64, no PEM header |
| `saml.sp.base.url` | the URL Fess is reached at; the three SP URLs are derived from it (default `http://localhost:8080`) |
| `saml.sp.entityid` | overrides the derived `<base>/sso/metadata` |
| `saml.sp.assertion_consumer_service.url` | overrides the derived `<base>/sso/` |
| `saml.sp.single_logout_service.url` | overrides the derived `<base>/sso/logout` |
| `saml.sp.nameidformat` | the requested NameID format (default `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`) |
| `saml.sp.privatekey` | the SP private key, base64 PKCS#8, no PEM header; needed to sign messages, to sign the metadata and to decrypt an encrypted assertion |
| `saml.sp.x509cert` | the SP certificate that goes with it |
| `saml.attribute.group.name` | the assertion attribute holding the user's groups (default `memberOf`) |
| `saml.attribute.role.name` | the assertion attribute holding the user's roles |
| `saml.default.groups` | comma-separated groups added to every SAML login |
| `saml.default.roles` | comma-separated roles added to every SAML login |
| `saml.request.id.ttl` | how long an unanswered AuthnRequest ID stays usable, in seconds (default `3600`) |

Every other `saml.` key is passed through to java-saml as `onelogin.saml2.` + the rest of the name,
so `saml.strict`, `saml.debug` and the whole `saml.security.` family are set the same way. Turning
on `saml.security.authnrequest_signed`, `saml.security.want_messages_signed` and
`saml.security.want_assertions_signed` is worth doing in production; Fess reports the permissive
defaults once as `assertions_and_messages_not_required_signed` at WARN when the settings are built.

Those pass-through keys are read by scanning `system.properties`, so `-Dfess.system.saml....` does
not reach them. It does reach `saml.request.id.ttl`, `saml.attribute.group.name`,
`saml.attribute.role.name`, `saml.default.groups` and `saml.default.roles`, which are read through
`FessProp.getSystemProperty`.

The full `saml.*` reference, including a worked configuration for each supported IdP, is the SAML
SSO page of the [Fess documentation](https://fess.codelibs.org/).

### Session cookies

The IdP returns the assertion as a cross-site POST. A `SameSite=Lax` cookie is not sent on such a
request, so the shipped default has to be changed for SAML. In `tomcat_config.properties`
(`lib/classes/` in the ZIP package, `/etc/fess/` in the DEB and RPM packages):

```
tomcat.sameSiteCookies = none
```

Browsers only accept `none` on a `Secure` cookie, so Fess has to be served over HTTPS. Over plain
HTTP this setting makes it impossible to log in at all.

## Version

| Fess | Plugin |
| --- | --- |
| 15.9.x | 15.9.x |

Match the minor version. Installing this plugin into Fess 15.8 or earlier breaks SSO with a 500:
those versions register `samlAuthenticator` in their own `fess_sso++.xml`, and a second registration
from this plugin makes `getComponent` fail with `TooManyRegistrationComponentException` — not only
for `sso.type=saml`, but for every SSO type, because the failure is in building the container's view
of that component name.

## How it plugs in

Nothing here is wired by class name from Fess. The plugin ships one additive LastaDi file that Fess
merges from every jar on the class path: `fess_sso++.xml` registers `samlAuthenticator`.
`SsoManager` resolves an authenticator as `<sso.type>Authenticator`, so that component name is what
makes `sso.type=saml` resolve. It is a singleton because `init()` registers the instance with the
`SsoManager`, and because the pending AuthnRequest IDs and the replay cache it holds have to be the
same ones on the request that answers the IdP.

`fess_sso.xml` is included from the webapp's `app.xml` and from no other Di xml, so the crawler,
thumbnail, suggest and chunk processes never build this component. That is why the jar carries
`Fess-WebAppJar: true` and why `jakarta.servlet-api` is a `provided` dependency: the servlet
container supplies it where the authenticator actually runs.

`SsoAuthenticator`, `SsoManager`, `SsoAction`, the SSO part of the admin general page and the
`sso.*` configuration keys all stay in Fess. Only the authenticator, the credential it produces and
the SAML library ship here. java-saml, java-saml-core and xmlsec are shaded in without relocation,
because Santuario reads its own algorithm registry out of a bundled config.xml and instantiates
every entry by name. Woodstox, which xmlsec asks for at runtime, is left out: java-saml uses only
Santuario's DOM API, and shipping Woodstox would announce a StAX implementation to the whole webapp
without the stax2-api that goes with it.
