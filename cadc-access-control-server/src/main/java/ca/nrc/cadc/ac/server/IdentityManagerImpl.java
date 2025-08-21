/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2023.                            (c) 2023.
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

package ca.nrc.cadc.ac.server;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.client.GroupMemberships;
import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.AuthorizationTokenPrincipal;
import ca.nrc.cadc.auth.DNPrincipal;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.IdentityManager;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.auth.OpenIdPrincipal;
import ca.nrc.cadc.auth.PosixPrincipal;
import ca.nrc.cadc.auth.TokenValidator;
import ca.nrc.cadc.profiler.Profiler;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import java.net.URI;
import java.security.AccessControlException;
import java.security.Principal;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Logger;
import org.opencadc.auth.StandardIdentityManager;

/**
 * Internal implementation of IdentityManager for AuthenticationUtil in cadc-util.
 *
 * @author pdowler
 */
public class IdentityManagerImpl implements IdentityManager {

    private static final Logger log = Logger.getLogger(IdentityManagerImpl.class);

    private static final Set<URI> SEC_METHODS;

    static {
        Set<URI> tmp = new TreeSet<>();
        tmp.add(Standards.SECURITY_METHOD_ANON);
        tmp.add(Standards.SECURITY_METHOD_CERT);
        tmp.add(Standards.SECURITY_METHOD_COOKIE);
        tmp.add(Standards.SECURITY_METHOD_TOKEN);
        SEC_METHODS = Collections.unmodifiableSet(tmp);
    }

    public IdentityManagerImpl() {
    }

    @Override
    public Set<URI> getSecurityMethods() {
        return SEC_METHODS;
    }

    @Override
    public Subject validate(Subject subject) throws AccessControlException {
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

    /**
     * @param subject Subject to augment
     * @return the possibly modified subject
     */
    @Override
    public Subject augment(Subject subject) {
        final Profiler profiler = new Profiler(IdentityManagerImpl.class);
        log.debug("ac augment subject: " + subject);
        AuthMethod am = AuthenticationUtil.getAuthMethod(subject);
        if (am == null || AuthMethod.ANON.equals(am)) {
            log.debug("returning anon subject");
            return subject;
        }

        if (subject != null && !subject.getPrincipals().isEmpty()) {
            Profiler prof = new Profiler(IdentityManagerImpl.class);
            this.augmentSubject(subject);
            prof.checkpoint("userDAO.augmentSubject()");

            if (subject.getPrincipals(NumericPrincipal.class).isEmpty()) // no matching internal account
            {
                log.debug("NumericPrincipal not found - dropping to anon: " + subject);
                subject = AuthenticationUtil.getAnonSubject();
            }
        }
        profiler.checkpoint("getSubject");

        return subject;
    }

    public void augmentSubject(final Subject subject) {
        try {
            final Profiler profiler = new Profiler(IdentityManagerImpl.class);
            PluginFactory pluginFactory = new PluginFactory();
            UserPersistence userPersistence = pluginFactory.createUserPersistence();
            Principal ldapPrincipal = getLdapPrincipal(subject);

            // CADC-10630 Remove potentially incorrect userID
            // in HttpPrincipal in subject.
            subject.getPrincipals().removeAll(subject.getPrincipals(HttpPrincipal.class));

            User user = userPersistence.getAugmentedUser(ldapPrincipal, true);
            if (user.getIdentities() != null) {
                log.debug("Found " + user.getIdentities().size() + " principals after argument");
            } else {
                log.debug("Null identities after augment");
            }
            subject.getPrincipals().addAll(user.getIdentities());

            if (user.appData != null) {
                log.debug("found: " + user.appData.getClass().getName());
                try {
                    GroupMemberships gms = (GroupMemberships) user.appData;
                    for (Group g : gms.getMemberships(Role.ADMIN)) {
                        log.debug("GroupMemberships admin: " + g.getID());
                    }
                    for (Group g : gms.getMemberships(Role.MEMBER)) {
                        log.debug("GroupMemberships member: " + g.getID());
                    }
                    subject.getPrivateCredentials().add(gms);
                } catch (Exception bug) {
                    throw new RuntimeException("BUG: found User.appData but could not store in Subject as GroupMemberships cache", bug);

                }
            } else {
                throw new RuntimeException("BUG: expected getAugmentedUser to return GroupMembership cache");
            }
            user.appData = null; // avoid loop that prevents GC???
            profiler.checkpoint("augmentSubject");
        } catch (UserNotFoundException e) {
            // ignore, could be an anonymous user
            log.debug("could not find user for augmenting", e);
        } catch (Exception e) {
            throw new IllegalStateException("Internal error", e);
        }
    }

    @Override
    public Subject toSubject(Object owner) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Object toOwner(Subject subject) {
        throw new UnsupportedOperationException();
    }

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

    // prefer principals that map to ldap attributes
    private static Principal getLdapPrincipal(Subject s) {
        Principal ret = null;
        for (Principal p : s.getPrincipals()) {
            ret = p;
            if ((p instanceof HttpPrincipal) || (p instanceof X500Principal)
                    || (p instanceof NumericPrincipal) || (p instanceof DNPrincipal)
                    || (p instanceof PosixPrincipal) || (p instanceof OpenIdPrincipal)) {
                return ret;
            }
        }
        return ret;
    }

}
