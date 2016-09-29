/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2014.                            (c) 2014.
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

import javax.security.auth.Subject;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.client.GroupMemberships;
import ca.nrc.cadc.ac.server.PluginFactory;
import ca.nrc.cadc.ac.server.UserPersistence;
import ca.nrc.cadc.profiler.Profiler;

/**
 * Implementation of default Authenticator for AuthenticationUtil in cadcUtil.
 * This class augments the subject with additional identities using the
 * access control library.
 *
 * @author pdowler
 */
public class AuthenticatorImpl implements Authenticator
{
    private static final Logger log = Logger.getLogger(AuthenticatorImpl.class);

    public AuthenticatorImpl() { }

    /**
     * @param subject
     * @return the possibly modified subject
     */
    public Subject getSubject(Subject subject)
    {
        Profiler profiler = new Profiler(AuthenticatorImpl.class);
        log.debug("ac augment subject: " + subject);
        AuthMethod am = AuthenticationUtil.getAuthMethod(subject);
        if (am == null || AuthMethod.ANON.equals(am))
        {
            log.debug("returning anon subject");
            return subject;
        }

        if (subject != null && subject.getPrincipals().size() > 0)
        {
            Profiler prof = new Profiler(AuthenticatorImpl.class);
            this.augmentSubject(subject);
            prof.checkpoint("userDAO.augmentSubject()");

            // if the caller had an invalid or forged CADC_SSO cookie, we could get
            // in here and then not match any known identity: drop to anon
            if ( subject.getPrincipals(NumericPrincipal.class).isEmpty() ) // no matching internal account
            {
                log.debug("NumericPrincipal not found - dropping to anon: " + subject);
                subject = AuthenticationUtil.getAnonSubject();
            }
        }
        profiler.checkpoint("getSubject");

        return subject;
    }

    public void augmentSubject(final Subject subject)
    {
        try
        {
            Profiler profiler = new Profiler(AuthenticatorImpl.class);
            PluginFactory pluginFactory = new PluginFactory();
            UserPersistence userPersistence = pluginFactory.createUserPersistence();
            User user = userPersistence.getAugmentedUser(subject.getPrincipals().iterator().next());
            if (user.getIdentities() != null)
            {
                log.debug("Found " + user.getIdentities().size() + " principals after argument");
            }
            else
            {
                log.debug("Null identities after augment");
            }
            subject.getPrincipals().addAll(user.getIdentities());
            if (user.appData != null)
            {
                log.debug("found: " + user.appData.getClass().getName());
                try
                {
                    GroupMemberships gms = (GroupMemberships) user.appData;
                    for (Group g : gms.getMemberships(Role.ADMIN))
                        log.debug("GroupMemberships admin: " + g.getID());
                    for (Group g : gms.getMemberships(Role.MEMBER))
                        log.debug("GroupMemberships member: " + g.getID());
                    subject.getPrivateCredentials().add(gms);
                }
                catch(Exception bug)
                {
                    throw new RuntimeException("BUG: found User.appData but could not store in Subject as GroupMemberships cache", bug);

                }
            }
            user.appData = null; // avoid loop that prevents GC???
            profiler.checkpoint("augmentSubject");
        }
        catch (UserNotFoundException e)
        {
            // ignore, could be an anonymous user
            log.debug("could not find user for augmenting", e);
        }
        catch (Exception e)
        {
            throw new IllegalStateException("Internal error", e);
        }
    }

}
