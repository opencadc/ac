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
 *  $Revision: 4 $
 *
 ************************************************************************
 */

package ca.nrc.cadc.ac;

import ca.nrc.cadc.ac.client.UserClient;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.AuthorizationToken;
import ca.nrc.cadc.auth.AuthorizationTokenPrincipal;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.IdentityManager;
import ca.nrc.cadc.auth.NotAuthenticatedException;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.auth.OpenIdPrincipal;
import ca.nrc.cadc.auth.PosixPrincipal;
import ca.nrc.cadc.auth.TokenValidator;
import ca.nrc.cadc.cred.client.CredUtil;
import ca.nrc.cadc.profiler.Profiler;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import java.net.URI;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Logger;
import org.opencadc.auth.StandardIdentityManager;

/**
 * AC implementation of the IdentityManager interface. This
 * implementation returns the NumericPrincipal.
 *
 * @author pdowler
 */
public class ACIdentityManager implements IdentityManager {

    private static final Logger log = Logger.getLogger(ACIdentityManager.class);

    private static final Set<URI> SEC_METHODS;
    private static final String PP_PROP = ACIdentityManager.class.getName() + ".requireCompletePosixPrincipal";

    private final boolean requireCompletePosixPrincipal;

    static {
        Set<URI> tmp = new TreeSet<>();
        tmp.add(Standards.SECURITY_METHOD_ANON);
        tmp.add(Standards.SECURITY_METHOD_CERT);
        tmp.add(Standards.SECURITY_METHOD_COOKIE);
        tmp.add(Standards.SECURITY_METHOD_TOKEN);
        SEC_METHODS = Collections.unmodifiableSet(tmp);
    }

    public ACIdentityManager() {
        String pval = System.getProperty(PP_PROP);
        if (pval != null) {
            pval = pval.trim();
        }
        this.requireCompletePosixPrincipal = "true".equals(pval);
    }

    @Override
    public Set<URI> getSecurityMethods() {
        return SEC_METHODS;
    }

    @Override
    public Subject validate(Subject subject) throws NotAuthenticatedException {
        Subject sub = TokenValidator.validateTokens(subject);
        if (!sub.getPrincipals(AuthorizationTokenPrincipal.class).isEmpty()) {
            LocalAuthority loc = new LocalAuthority();
            if (loc.getResourceID(Standards.SECURITY_METHOD_OPENID) != null) {
                StandardIdentityManager sim = new StandardIdentityManager();
                return sim.validate(sub);
            }
        }
        return sub;
    }

    @Override
    public Subject augment(final Subject subject) {
        log.debug("augment START: " + subject);
        if (subject == null) {
            log.debug("augment DONE: null");
            return null;
        }
        if (subject.getPrincipals().isEmpty()) {
            log.debug("augment DONE no principals: " + subject);
            return subject;
        }

        NumericPrincipal np = getNumericPrincipal(subject);
        boolean needAugment = (np == null || subject.getPrincipals().size() == 1);

        if (requireCompletePosixPrincipal) {
            PosixPrincipal pp = getPosixPrincipal(subject);
            log.debug("augment check posix: " + pp);
            needAugment = needAugment || pp == null || pp.defaultGroup == null || pp.username == null; // missing or incomplete
        } else {
            log.debug("augment: requireCompletePosixPrincipal=false");
        }

        if (!needAugment) {
            log.debug("augment DONE needAugment=false: " + subject);
            return subject;
        }

        try {
            PrivilegedExceptionAction<Object> action = new PrivilegedExceptionAction<Object>() {
                public Object run() throws Exception {
                    LocalAuthority localAuth = new LocalAuthority();
                    URI serviceURI = localAuth.getServiceURI(Standards.UMS_USERS_01.toASCIIString());

                    UserClient userClient = new UserClient(serviceURI);
                    userClient.augmentSubject(subject);
                    return null;
                }
            };

            Subject actionSubject = subject;
            if (subject.getPublicCredentials(AuthorizationToken.class).isEmpty()) {
                actionSubject = CredUtil.createOpsSubject();
            }
            Subject.doAs(actionSubject, action);
            log.debug("augment DONE w/ UserClient: " + subject);
            return subject;
        } catch (PrivilegedActionException e) {
            String msg = "Error augmenting subject " + subject;
            throw new RuntimeException(msg, e);
        }
    }

    private NumericPrincipal getNumericPrincipal(Subject subject) {
        if (subject == null) {
            return null;
        }
        Set<NumericPrincipal> nps = subject.getPrincipals(NumericPrincipal.class);
        if (!nps.isEmpty()) {
            return nps.iterator().next();
        }
        return null;
    }

    private PosixPrincipal getPosixPrincipal(Subject subject) {
        if (subject == null) {
            return null;
        }
        Set<PosixPrincipal> nps = subject.getPrincipals(PosixPrincipal.class);
        if (!nps.isEmpty()) {
            return nps.iterator().next();
        }
        return null;
    }

    /**
     * @param subject
     * @return an Integer internal CADC ID
     */
    @Override
    public Object toOwner(Subject subject) {
        if (subject == null) {
            return null;
        }

        X500Principal x500Principal = null;
        OpenIdPrincipal openIdPrincipal = null;
        Set<Principal> principals = subject.getPrincipals();
        for (Principal principal : principals) {
            if (principal instanceof NumericPrincipal) {
                NumericPrincipal cp = (NumericPrincipal) principal;
                UUID id = cp.getUUID();
                return id.getLeastSignificantBits();
            }
            if (principal instanceof X500Principal) {
                x500Principal = (X500Principal) principal;
            }
            if (principal instanceof OpenIdPrincipal) {
                openIdPrincipal = (OpenIdPrincipal) principal;
            }
        }

        NumericPrincipal numericPrincipal;
        if (openIdPrincipal != null && x500Principal != null) {
            throw new NotAuthenticatedException(
                    "Simultaneous OpenIdPrincipal and X500Principal authentication not supported: "
                    + openIdPrincipal + ", " + x500Principal);
        }

        if (openIdPrincipal != null) {
            // The user has connected with a valid OpenID but does
            // not have an account (no numeric principal).
            // Create an auto-approved account with their OpenIdPrincipal.
            numericPrincipal = createAuthUser(openIdPrincipal);
        } else if (x500Principal != null) {
            // The user has connected with a valid client cert but does
            // not have an account (no numeric principal).
            // Create an auto-approved account with their x500Principal.
            numericPrincipal = createAuthUser(x500Principal);
        } else {
            return null;
        }
        subject.getPrincipals().add(numericPrincipal);
        return numericPrincipal.getUUID().getLeastSignificantBits();
    }

    private NumericPrincipal createAuthUser(final Principal principal) {
        if (!(principal instanceof X500Principal) && !(principal instanceof OpenIdPrincipal)) {
            throw new IllegalArgumentException("principal must be a valid principal "
                    + "(X500Principal or OpenIdPrincipal)");
        }
        PrivilegedExceptionAction<NumericPrincipal> action = () -> {
            LocalAuthority localAuth = new LocalAuthority();
            URI serviceURI = localAuth.getResourceID(Standards.UMS_USERS_01);

            UserClient userClient = new UserClient(serviceURI);
            User newUser = userClient.createUser(principal);

            Set<NumericPrincipal> set = newUser.getIdentities(NumericPrincipal.class);
            if (set.isEmpty()) {
                throw new IllegalStateException("missing internal id");
            }
            return set.iterator().next();
        };

        Subject acSubject;
        if (principal instanceof OpenIdPrincipal) {
            acSubject = AuthenticationUtil.getCurrentSubject();
        } else {
            acSubject = CredUtil.createOpsSubject();
        }
        try {
            return Subject.doAs(acSubject, action);
        } catch (Exception e) {
            throw new IllegalStateException("failed to create internal id for user " + principal.getName(), e);
        }
    }

    /**
     * Get a consistent string representation of the user.
     *
     * @param subject
     * @return identity or null for anon
     */
    @Override
    public String toDisplayString(Subject subject) {
        if (subject != null) {
            Set<HttpPrincipal> up = subject.getPrincipals(HttpPrincipal.class);
            if (!up.isEmpty()) {
                return up.iterator().next().getName();
            }
            // default
            Set<Principal> ps2 = subject.getPrincipals();
            if (!ps2.isEmpty()) {
                return ps2.iterator().next().getName();
            }
        }
        return null;
    }

    /**
     * Reconstruct the subject from the stored object. This method also
     * re-populates the subject with all known alternate principals.
     *
     * @param o the stored object
     * @return the complete subject
     */
    @Override
    public Subject toSubject(Object o) {
        if (o == null) {
            return null;
        }
        Long n = null;
        if (o instanceof String) {
            n = Long.valueOf((String) o);
        } else if (o instanceof Integer) {
            n = ((Integer) o).longValue();
        } else if (o instanceof Long) {
            n = (Long) o;
        } else {
            throw new IllegalStateException("cannot reconstruct Subject from a "
                    + o.getClass().getName());
        }

        if (n <= 0) {
            // identities <= 0 are internal
            return new Subject();
        }

        UUID uuid = new UUID(0L, n);
        NumericPrincipal p = new NumericPrincipal(uuid);

        Subject s = AuthenticationUtil.getCurrentSubject();
        if (s != null) {
            for (Principal cp : s.getPrincipals()) {
                if (AuthenticationUtil.equals(p, cp)) {
                    log.debug("[cache hit] caller Subject matches " + p + ": " + s);
                    return s;
                }
            }
        }

        Set<Principal> pset = new HashSet<Principal>();
        pset.add(p);
        Subject ret = new Subject(false, pset, new HashSet(), new HashSet());

        Profiler prof = new Profiler(ACIdentityManager.class);
        ret = augment(ret);
        prof.checkpoint("CadcIdentityManager.augmentSubject");

        return ret;
    }
}
