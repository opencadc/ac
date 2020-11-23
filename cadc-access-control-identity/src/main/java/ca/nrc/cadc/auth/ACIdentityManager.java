/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2017.                            (c) 2017.
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

package ca.nrc.cadc.auth;

import java.io.File;
import java.net.URI;
import java.net.URL;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.sql.Types;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.UUID;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.client.UserClient;
import ca.nrc.cadc.cred.client.CredUtil;
import ca.nrc.cadc.profiler.Profiler;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.vosi.avail.CheckResource;
import ca.nrc.cadc.vosi.avail.CheckWebService;

/**
 * AC implementation of the IdentityManager interface. This
 * implementation returns the NumericPrincipal.
 *
 * @author pdowler
 */
public class ACIdentityManager implements IdentityManager {

    private static final Logger log = Logger.getLogger(ACIdentityManager.class);

    public ACIdentityManager() {
    }

    /**
     * Returns a storage type constant from java.sql.Types.
     *
     * @return Types.INTEGER
     */
    @Override
    public int getOwnerType() {
        return Types.INTEGER;
    }

    /**
     * Returns a value of type specified by getOwnerType() for storage.
     *
     * @param subject
     * @return an Integer internal CADC ID
     */
    @Override
    public Object toOwner(Subject subject) {
        X500Principal x500Principal = null;
        if (subject != null) {
            Set<Principal> principals = subject.getPrincipals();
            for (Principal principal : principals) {
                if (principal instanceof NumericPrincipal) {
                    NumericPrincipal cp = (NumericPrincipal) principal;
                    UUID id = cp.getUUID();
                    Long l = Long.valueOf(id.getLeastSignificantBits());
                    return l.intValue();
                }
                if (principal instanceof X500Principal) {
                    x500Principal = (X500Principal) principal;
                }
            }
        }

        if (x500Principal == null) {
            return null;
        }

        // The user has connected with a valid client cert but does
        // not have an account (no numeric principal).
        // Create an auto-approved account with their x500Principal.
        NumericPrincipal numericPrincipal = createX500User(x500Principal);
        subject.getPrincipals().add(numericPrincipal);
        return Long.valueOf(numericPrincipal.getUUID().getLeastSignificantBits());
    }

    private NumericPrincipal createX500User(final X500Principal x500Principal) {
        PrivilegedExceptionAction<NumericPrincipal> action = new PrivilegedExceptionAction<NumericPrincipal>() {
            @Override
            public NumericPrincipal run() throws Exception {
                LocalAuthority localAuth = new LocalAuthority();
                URI serviceURI = localAuth.getServiceURI(Standards.UMS_USERS_01.toASCIIString());

                UserClient userClient = new UserClient(serviceURI);
                User newUser = userClient.createUser(x500Principal);

                Set<NumericPrincipal> set = newUser.getIdentities(NumericPrincipal.class);
                if (set.isEmpty()) {
                    throw new IllegalStateException("missing internal id");
                }
                return set.iterator().next();
            }
        };

        //Subject servopsSubject = SSLUtil.createSubject(privilegedPemFile);
        Subject servopsSubject = CredUtil.createOpsSubject();
        try {
            return Subject.doAs(servopsSubject, action);
        } catch (Exception e) {
            throw new IllegalStateException("failed to create internal id for user " + x500Principal.getName(), e);
        }
    }

    /**
     * Get a consistent string representation of the user.
     *
     * @param subject
     * @return an X509 distinguished name
     */
    @Override
    public String toOwnerString(Subject subject) {
        if (subject != null) {
            Set<Principal> principals = subject.getPrincipals();
            for (Principal principal : principals) {
                if (principal instanceof X500Principal) {
                    return principal.getName();
                }
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
        try {
            Integer i = null;
            if (o instanceof String) {
                i = Integer.valueOf((String) o);
            } else if (o instanceof Integer) {
                i = (Integer) o;
            } else {
                throw new IllegalStateException("cannot reconstruct Subject from a "
                        + o.getClass().getName());
            }
            
            if (i <= 0) {
                // identities <= 0 are internal
                return new Subject();
            }

            UUID uuid = new UUID(0L, (long) i);
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
            augmentSubject(ret);
            prof.checkpoint("CadcIdentityManager.augmentSubject");

            return ret;
        } finally {

        }
    }

    public void augmentSubject(final Subject subject) {

        if (subject == null ) {
            return;
        }

        // If the principal list is in the subject has aNumeric Principal
        // AND the list is greater than 1, then LDAP doesn't need to be
        // called here (subject has already been augmented)
        Set<Principal> principalSet = subject.getPrincipals();
        Set<NumericPrincipal> nPrincipalSet = subject.getPrincipals(NumericPrincipal.class);
        if (principalSet.size() > 1 && !nPrincipalSet.isEmpty()) {
            return;
        }
        
        // Create a supporting HttpPrincipal if we have a BearerTokenPrincipal
        Principal p = principalSet.iterator().next();
        if (p instanceof BearerTokenPrincipal) {
            principalSet.add(((BearerTokenPrincipal) p).user);
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

            Subject servopsSubject = CredUtil.createOpsSubject();
            Subject.doAs(servopsSubject, action);
        } catch (PrivilegedActionException e) {
            String msg = "Error augmenting subject " + subject;
            throw new RuntimeException(msg, e);
        }
    }

    /**
     * The returned CheckResource is the same as the one from AuthenticatorImpl.
     *
     * @return the CheckResource
     */
    public static CheckResource getAvailabilityCheck() {
        RegistryClient regClient = new RegistryClient();
        LocalAuthority localAuth = new LocalAuthority();
        URI serviceURI = localAuth.getServiceURI(Standards.UMS_USERS_01.toASCIIString());
        URL availURL = regClient.getServiceURL(serviceURI, Standards.VOSI_AVAILABILITY, AuthMethod.ANON);
        return new CheckWebService(availURL.toExternalForm());
    }
}
