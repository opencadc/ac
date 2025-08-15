/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2025.                            (c) 2025.
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
*  $Revision: 5 $
*
************************************************************************
*/

package ca.nrc.cadc.ac.integration;


import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.File;
import java.net.URI;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import javax.security.auth.Subject;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Test;
import org.opencadc.gms.GroupURI;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupAlreadyExistsException;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.client.GMSClient;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import ca.nrc.cadc.util.FileUtil;
import ca.nrc.cadc.util.Log4jInit;
import java.security.AccessControlException;

/**
 *
 * @author pdowler
 */
public class GroupNamePrefixIntTest
{
    private static final Logger log = Logger.getLogger(GroupNamePrefixIntTest.class);

    static
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
    }

    private Subject user1Subject;
    private Subject user2Subject;

    public GroupNamePrefixIntTest()
    {
        try
        {
            File u1 = FileUtil.getFileFromResource("user1.pem", GmsClientIntTest.class);
            File u2 = FileUtil.getFileFromResource("user2.pem", GmsClientIntTest.class);
            user1Subject = SSLUtil.createSubject(u1);
            user2Subject = SSLUtil.createSubject(u2);
        }
        catch(Exception unexpected)
        {
            log.error("setup failure", unexpected);
            throw new RuntimeException("setup failure", unexpected);
        }
    }

    @Test
    public void testAllow()
    {
        Group g = null;

        try
        {
            LocalAuthority localAuthority = new LocalAuthority();
            URI gmsServiceURI = localAuthority.getServiceURI(Standards.GMS_GROUPS_01.toString());
            g = new Group(new GroupURI(gmsServiceURI + "?ALLOW-TEST-" + UUID.randomUUID().toString()));

            Group g2 = createGroupAs(g, user1Subject);
            assertNotNull(g2);

            Group pg = getGroupAs(g.getID().getName(), user1Subject, true);
            assertNotNull(pg);
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            fail("unexpected exception: " + unexpected);
        }
        finally
        {
            try
            {
                if (g != null)
                {
                    deleteGroupAs(g.getID().getName(), user1Subject);
                }
            }
            catch(Exception ignore) { }
        }
    }

    @Test
    public void testDeny()
    {
        Group g = null;

        try
        {
            try
            {
                LocalAuthority localAuthority = new LocalAuthority();
                URI gmsServiceURI =
                        localAuthority.getServiceURI(Standards.GMS_GROUPS_01.toString());
                g = new Group(new GroupURI(gmsServiceURI + "?ALLOW-TEST-"
                                           + UUID.randomUUID().toString()));

                createGroupAs(g, user2Subject);
            }
            catch(AccessControlException expected)
            {
                log.info("caught expected exception: " + expected);
            }

            try
            {
                Group pg = getGroupAs(g.getID().getName(), user2Subject, false);
                fail("expected creategroup to fail && GroupNotFoundException, got: " + pg);
            }
            catch(GroupNotFoundException expected)
            {
                log.info("caught expected exception: " + expected);
            }
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            fail("unexpected exception: " + unexpected);
        }
        finally
        {
            try
            {
                if (g != null)
                {
                    deleteGroupAs(g.getID().getName(), user2Subject);
                }
            }
            catch(Exception ignore) { }
        }
    }

    private Group createGroupAs(final Group group, final Subject subject)
            throws Exception
    {
        try
        {
            return Subject.doAs(subject, new PrivilegedExceptionAction<Group>()
            {
                @Override
                public Group run() throws Exception
                {
                    return getGMSClient().createGroup(group);
                }
            });
        }
        catch (PrivilegedActionException e)
        {
            throw e.getException();
        }
    }

    private void deleteGroupAs(final String groupName, final Subject subject)
            throws Exception
    {
        try
        {
            Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
            {
                @Override
                public Object run() throws Exception
                {
                    getGMSClient().deleteGroup(groupName);
                    return null;
                }
            });
        }
        catch (PrivilegedActionException e)
        {
            throw e.getException();
        }
    }

    private Group getGroupAs(final String groupID, final Subject user, final boolean delay)
            throws Exception
    {
        try
        {
            return Subject.doAs(user,
                                new PrivilegedExceptionAction<Group>()
                                {
                                    @Override
                                    public Group run() throws Exception
                                    {
                                        Group group = null;
                                            if (delay) {
                                            // add delay to compensate for 
                                            // eventual consistency of
                                            // content in multiple ldap hosts
                                            // try it several times
                                            int n = 1;
                                            boolean success = false;
                                            while (!success && n < 10) {
                                                try {
                                                    TimeUnit.MILLISECONDS.sleep(20 * Math.round(Math.pow(2.0, n)));
                                                    group = getGMSClient().getGroup(groupID);
                                                    success = true;
                                                } catch(Exception ex) {
                                                    n++;
                                                }
                                            }
                                        } else {
                                            group = getGMSClient().getGroup(groupID);
                                        }
                                        return group;
                                    }
                                });
        }
        catch (PrivilegedActionException e)
        {
            throw e.getException();
        }
    }

    private GMSClient getGMSClient()
    {
        LocalAuthority localAuthority = new LocalAuthority();
        final URI gmsServiceURI =
                localAuthority.getServiceURI(Standards.GMS_GROUPS_01.toString());

        return new GMSClient(gmsServiceURI);
    }
}
