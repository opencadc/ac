/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2024.                            (c) 2024.
 *  Government of Canada                 Gouvernement du Canada
 *  National Research Council            Conseil national de recherches
 *  Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 *  All rights reserved                  Tous droits réservés
 *
 *  NRC disclaims any warranties,        Le CNRC dénie toute garantie
 *  expressed, implied, or               énoncée, implicite ou légale,
 *  statutory, of any kind with          de quelque nature que ce
 *  respect to the software,             soit, concernant le logiciel,
 *  including without limitation         y compris sans restriction
 *  any warranty of merchantability      toute garantie de valeur
 *  or fitness for a particular          marchande ou de pertinence
 *  purpose. NRC shall not be            pour un usage particulier.
 *  liable in any event for any          Le CNRC ne pourra en aucun cas
 *  damages, whether direct or           être tenu responsable de tout
 *  indirect, special or general,        dommage, direct ou indirect,
 *  consequential or incidental,         particulier ou général,
 *  arising from the use of the          accessoire ou fortuit, résultant
 *  software.  Neither the name          de l'utilisation du logiciel. Ni
 *  of the National Research             le nom du Conseil National de
 *  Council of Canada nor the            Recherches du Canada ni les noms
 *  names of its contributors may        de ses  participants ne peuvent
 *  be used to endorse or promote        être utilisés pour approuver ou
 *  products derived from this           promouvoir les produits dérivés
 *  software without specific prior      de ce logiciel sans autorisation
 *  written permission.                  préalable et particulière
 *                                       par écrit.
 *
 *  This file is part of the             Ce fichier fait partie du projet
 *  OpenCADC project.                    OpenCADC.
 *
 *  OpenCADC is free software:           OpenCADC est un logiciel libre ;
 *  you can redistribute it and/or       vous pouvez le redistribuer ou le
 *  modify it under the terms of         modifier suivant les termes de
 *  the GNU Affero General Public        la “GNU Affero General Public
 *  License as published by the          License” telle que publiée
 *  Free Software Foundation,            par la Free Software Foundation
 *  either version 3 of the              : soit la version 3 de cette
 *  License, or (at your option)         licence, soit (à votre gré)
 *  any later version.                   toute version ultérieure.
 *
 *  OpenCADC is distributed in the       OpenCADC est distribué
 *  hope that it will be useful,         dans l’espoir qu’il vous
 *  but WITHOUT ANY WARRANTY;            sera utile, mais SANS AUCUNE
 *  without even the implied             GARANTIE : sans même la garantie
 *  warranty of MERCHANTABILITY          implicite de COMMERCIALISABILITÉ
 *  or FITNESS FOR A PARTICULAR          ni d’ADÉQUATION À UN OBJECTIF
 *  PURPOSE.  See the GNU Affero         PARTICULIER. Consultez la Licence
 *  General Public License for           Générale Publique GNU Affero
 *  more details.                        pour plus de détails.
 *
 *  You should have received             Vous devriez avoir reçu une
 *  a copy of the GNU Affero             copie de la Licence Générale
 *  General Public License along         Publique GNU Affero avec
 *  with OpenCADC.  If not, see          OpenCADC ; si ce n’est
 *  <http://www.gnu.org/licenses/>.      pas le cas, consultez :
 *                                       <http://www.gnu.org/licenses/>.
 *
 ************************************************************************
 */

package org.opencadc.auth;

import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.AuthorizationToken;
import ca.nrc.cadc.auth.AuthorizationTokenPrincipal;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.IdentityManager;
import ca.nrc.cadc.auth.NotAuthenticatedException;
import ca.nrc.cadc.auth.OpenIdPrincipal;
import ca.nrc.cadc.auth.PosixPrincipal;
import ca.nrc.cadc.net.HttpGet;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.util.StringUtil;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.Principal;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.TreeSet;
import javax.security.auth.Subject;
import org.apache.log4j.Logger;
import org.json.JSONObject;

/**
 * Prototype IdentityManager for a standards-based system. This currently supports
 * validating tokens using a configured OIDC issuer, but the intent is to support
 * the range of IVOA-sanctioned authentication mechanisms.
 *
 * @author pdowler
 */
public class StandardIdentityManager implements IdentityManager {
    private static final Logger log = Logger.getLogger(StandardIdentityManager.class);

    private static final Set<URI> SEC_METHODS;

    static {
        Set<URI> tmp = new TreeSet<>();
        tmp.add(Standards.SECURITY_METHOD_ANON);
        tmp.add(Standards.SECURITY_METHOD_TOKEN);
        SEC_METHODS = Collections.unmodifiableSet(tmp);
    }

    private final OIDCClient oidcClient;

    // need these to construct an AuthorizationToken
    private final RegistryClient reg = new RegistryClient();
    private final List<String> oidcDomains = new ArrayList<>();
    private URI oidcScope;

    private static final String OID_OWNER_DELIM = " ";  // delimiter between issuer and openID that form the owner str

    public StandardIdentityManager() {
        LocalAuthority loc = new LocalAuthority();
        oidcClient = new OIDCClient(loc.getResourceID(Standards.SECURITY_METHOD_OPENID));

        URL u = oidcClient.getIssuerURL();
        oidcDomains.add(u.getHost());

        // add known and assume trusted A&A services
        String host = getProviderHostname(loc, Standards.GMS_SEARCH_10);
        if (host != null) {
            oidcDomains.add(host);
        }
        for (String dom : oidcDomains) {
            log.debug("OIDC domain: " + dom);
        }
    }

    @Override
    public Set<URI> getSecurityMethods() {
        return SEC_METHODS;
    }

    // lookup the local/trusted provider of an API and extract the hostname
    private String getProviderHostname(LocalAuthority loc, URI standardID) {
        try {
            URI resourceID = loc.getResourceID(standardID);
            if (resourceID != null) {
                URL srv = reg.getServiceURL(resourceID, standardID, AuthMethod.TOKEN); // should be token
                if (srv != null) {
                    return srv.getHost();
                }
                log.debug("found: " + resourceID + " not found: " + standardID + " + " + AuthMethod.TOKEN);
            }
        } catch (NoSuchElementException ignore) {
            log.debug("not found: " + standardID);
        }
        return null;
    }

    @Override
    public Subject validate(Subject subject) throws NotAuthenticatedException {
        validateAuthorizationTokens(subject);
        return subject;
    }

    @Override
    public Subject augment(Subject subject) {
        // oidc tokens: validate gets HttpPrincipal and OpenIdPrincipal
        // cadc signed cookies/tokens: validate gets all identities
        boolean hasPP = !subject.getPrincipals(PosixPrincipal.class).isEmpty();
        boolean hasHP = !subject.getPrincipals(HttpPrincipal.class).isEmpty();
        boolean needAugment = (hasHP && !hasPP) || (hasPP && !hasHP);
        if (needAugment) {
            try {
                LocalAuthority loc = new LocalAuthority();
                URI posixUserMap = loc.getResourceID(Standards.POSIX_USERMAP);
                // LocalAuthority currently throws NoSuchElementException but let's be cautious
                if (posixUserMap != null) {
                    PosixMapperClient pmc;
                    String host = null;
                    if ("ivo".equals(posixUserMap.getScheme())) {
                        pmc = new PosixMapperClient(posixUserMap);
                    } else if ("https".equals(posixUserMap.getScheme()) || "http".equals(posixUserMap.getScheme())) {
                        URL url = posixUserMap.toURL();
                        host = url.getHost();
                        pmc = new PosixMapperClient(url);
                    } else {
                        throw new RuntimeException("CONFIG: unsupported posix-mapping identifier scheme: " + posixUserMap);
                    }
                    Subject cur = AuthenticationUtil.getCurrentSubject();
                    if (cur == null && hasHP) {
                        // not in a Subject.doAs
                        // use case: augment authenticated user after validate at start of request
                        Set<AuthorizationToken> ats = subject.getPublicCredentials(AuthorizationToken.class);
                        Iterator<AuthorizationToken> i = ats.iterator();
                        if (i.hasNext()) {
                            AuthorizationToken at = i.next();
                            if (host == null) {
                                host = getProviderHostname(loc, Standards.POSIX_USERMAP);
                            }
                            at.getDomains().add(host); // not sure if this should work
                        }
                        return Subject.doAs(subject, (PrivilegedExceptionAction<Subject>) () -> pmc.augment(subject));
                    }
                    if (cur != null) {
                        // already inside a Subject.doAs
                        // use case: augment from a persistently stored identity (eg uws job or vospace node)
                        return pmc.augment(subject);
                    }
                    throw new RuntimeException("BUG: did not call PosixMapperClient.augment(Subject)");
                } else {
                    // this is probably OK as most services do not need/use PosixPrincipal
                    log.debug("did not call PosixMapperClient.augment(Subject): no service configured to provide "
                            + Standards.POSIX_USERMAP.toASCIIString());
                }
            } catch (NoSuchElementException ex) {
                // this is probably OK as most services do not need/use PosixPrincipal
                log.debug("did not call PosixMapperClient.augment(Subject): no service configured to provide "
                        + Standards.POSIX_USERMAP.toASCIIString());
            } catch (Exception ex) {
                throw new RuntimeException("FAIL: PosixMapperClient.augment(Subject)", ex);
            }
        }

        // TODO: if X500Principal && CDP && privileged credentials we could augment CADC-style

        // default: cannot augment
        return subject;
    }

    @Override
    public Subject toSubject(Object owner) {
        Subject ret = new Subject();
        OpenIdPrincipal p;
        if (owner != null) {
            if (owner instanceof String) {
                String[] openIDComponents = ((String) owner).split(OID_OWNER_DELIM);  // "issuer openID"
                if (openIDComponents.length != 2) {
                    throw new RuntimeException("unexpected owner format: " + owner.getClass().getName() + " value: " + owner);
                }
                URL issuer;
                try {
                    issuer = new URL(openIDComponents[0]);
                } catch (MalformedURLException e) {
                    throw new RuntimeException(
                            "incorrect issuer format for owner: " + owner.getClass().getName() + " value: " + owner);
                }
                p = new OpenIdPrincipal(issuer, openIDComponents[1]);
            } else {
                throw new RuntimeException("unexpected owner type: " + owner.getClass().getName() + " value: " + owner);
            }

            // effectively augment by using the current subject as a "cache" of known identities
            Subject s = AuthenticationUtil.getCurrentSubject();
            if (s != null) {
                for (Principal cp : s.getPrincipals()) {
                    if (AuthenticationUtil.equals(p, cp)) {
                        log.debug("[cache hit] caller Subject matches " + p + ": " + s);
                        ret.getPrincipals().addAll(s.getPrincipals());
                        return ret;
                    }
                }
            }

            ret.getPrincipals().add(p);
            // this is sufficient for some purposes, but not for output using toDisplayString (eg vospace node owner)
            // TODO: use PosixMapperClient.augment() to try to add a PosixPrincipal and infer an HttpPrincipal?
        }
        return ret;
    }

    @Override
    public Object toOwner(Subject subject) {
        Set<OpenIdPrincipal> ps = subject.getPrincipals(OpenIdPrincipal.class);
        if (ps.isEmpty()) {
            return null;
        }
        OpenIdPrincipal openIdPrincipal = ps.iterator().next();
        return openIdPrincipal.getIssuer().toExternalForm() + OID_OWNER_DELIM + openIdPrincipal.getName();
    }

    @Override
    public String toDisplayString(Subject subject) {
        if (subject != null) {
            // prefer HttpPrincipal aka OIDC preferred_username for string output, eg logging
            Set<HttpPrincipal> ps = subject.getPrincipals(HttpPrincipal.class);
            if (!ps.isEmpty()) {
                return ps.iterator().next().getName(); // kind of ugh
            }

            // default
            Set<Principal> ps2 = subject.getPrincipals();
            if (!ps2.isEmpty()) {
                return ps2.iterator().next().getName();
            }
        }

        return null;
    }

    private void validateAuthorizationTokens(Subject s) {
        log.debug("validateOidcAccessToken - START");
        Set<AuthorizationTokenPrincipal> rawTokens = s.getPrincipals(AuthorizationTokenPrincipal.class);

        log.debug("token issuer: " + oidcClient.issuer + " rawTokens: " + rawTokens.size());
        if (!rawTokens.isEmpty()) {
            URL u = oidcClient.getUserInfoEndpoint();
            for (AuthorizationTokenPrincipal raw : rawTokens) {
                String credentials = null;
                String challengeType = null;

                // parse header
                log.debug("header key: " + raw.getHeaderKey());
                log.debug("header val: " + raw.getHeaderValue());
                if (AuthenticationUtil.AUTHORIZATION_HEADER.equalsIgnoreCase(raw.getHeaderKey())) {
                    String[] tval = raw.getHeaderValue().split(" ");
                    if (tval.length == 2) {
                        challengeType = tval[0];
                        credentials = tval[1];
                    } else {
                        throw new NotAuthenticatedException(challengeType, NotAuthenticatedException.AuthError.INVALID_REQUEST,
                                "invalid authorization");
                    }
                } // else: some other challenge
                log.debug("challenge type: " + challengeType);
                log.debug("credentials: " + credentials);

                // validate
                if (credentials != null) {
                    // Bearer tokens are handled specially by validating with the Identity Provider
                    if (AuthenticationUtil.CHALLENGE_TYPE_BEARER.equalsIgnoreCase(challengeType)) {
                        try {
                            HttpGet get = new HttpGet(u, true);
                            get.setRequestProperty("authorization", raw.getHeaderValue());
                            get.prepare();

                            InputStream istream = get.getInputStream();
                            String str = StringUtil.readFromInputStream(istream, "UTF-8");
                            JSONObject json = new JSONObject(str);
                            String sub = json.getString("sub");
                            String username = json.getString("preferred_username");
                            // TODO: register an X509 DN with IAM and see if I can get it back here

                            OpenIdPrincipal oip = new OpenIdPrincipal(oidcClient.getIssuerURL(), sub);
                            HttpPrincipal hp = new HttpPrincipal(username);

                            s.getPrincipals().remove(raw);
                            s.getPrincipals().add(oip);
                            s.getPrincipals().add(hp);

                            AuthorizationToken authToken = new AuthorizationToken(challengeType, credentials, oidcDomains, oidcScope);
                            s.getPublicCredentials().add(authToken);
                        } catch (NotAuthenticatedException ex) {
                            JSONObject json = new JSONObject(ex.getMessage());
                            String error = json.getString("error");
                            String details = json.getString("error_description");
                            // details usually includes the invalid access token: truncate
                            StringBuilder sb = new StringBuilder(error);
                            sb.append(" reason: ");
                            int max = Math.min(details.length(), 32);
                            sb.append(details.subSequence(0, max));
                            if (max < details.length()) {
                                sb.append("...");
                            }
                            throw new NotAuthenticatedException(challengeType, NotAuthenticatedException.AuthError.INVALID_TOKEN, sb.toString());
                        } catch (Exception ex) {
                            throw new NotAuthenticatedException(challengeType, NotAuthenticatedException.AuthError.INVALID_TOKEN, ex.getMessage(), ex);
                        }
                    } else {
                        // Otherwise it's a custom token, so we just create an AuthorizationToken and let whatever
                        // application is looking for it handle it.
                        AuthorizationToken authToken = new AuthorizationToken(challengeType, credentials, oidcDomains, oidcScope);
                        s.getPublicCredentials().add(authToken);

                        s.getPrincipals().remove(raw);
                    }
                }
            }
            log.debug("validateOidcAccessToken - DONE");
        }
    }
}
