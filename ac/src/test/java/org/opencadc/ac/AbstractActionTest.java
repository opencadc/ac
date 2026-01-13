/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2026.                            (c) 2026.
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

package org.opencadc.ac;

import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.IdentityType;
import ca.nrc.cadc.rest.SyncInput;
import org.junit.Test;
import static org.junit.Assert.fail;

/**
 * @author jburke
 */

import ca.nrc.cadc.ac.User;
import org.junit.Before;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import java.security.PrivilegedExceptionAction;
import java.util.Collections;

import static org.junit.Assert.*;

public class AbstractActionTest {

    private AbstractAction abstractAction;

    @Before
    public void setUp() {
        abstractAction = new AbstractAction() {
            @Override
            public void doAction() {

            }

            @Override
            public void setServiceURI() {
                // Mock implementation for abstract method
            }
        };
    }

    @Test
    public void testSetPrivilegedSubject() throws Exception {
        Subject privilegedSubject = new Subject();
        privilegedSubject.getPrincipals().add(new X500Principal("CN=Privileged"));

        abstractAction.config = new GroupsConfig() {
            @Override
            public java.util.List<Subject> getPrivilegedSubjects() {
                return Collections.singletonList(privilegedSubject);
            }
        };

        Subject.doAs(privilegedSubject, (PrivilegedExceptionAction<Object>) () -> {
            abstractAction.setPrivilegedSubject();
            return null;
        });

        assertNotNull(abstractAction.privilegedSubject);
        assertEquals(privilegedSubject, abstractAction.privilegedSubject);

        // Test with non-privileged subject
        abstractAction.privilegedSubject = null;
        Subject nonPrivilegedSubject = new Subject();
        Subject.doAs(nonPrivilegedSubject, (PrivilegedExceptionAction<Object>) () -> {
            abstractAction.setPrivilegedSubject();
            return null;
        });
        assertNull(abstractAction.privilegedSubject);
    }

    @Test
    public void testSetRequestInputValidPath() {
        checkPath("/groupName/userMembers/memberName", "groupName", "memberName", IdentityType.USERNAME.getValue());
        checkPath("/groupName/userMembers/memberName?idType=HTTP", "groupName", "memberName", IdentityType.USERNAME.getValue());
        checkPath("/groupName/userMembers/cn=memberName?idType=X500", "groupName", "cn=memberName", IdentityType.X500.getValue());
        checkPath("/groupName/userMembers/123?idType=CADC", "groupName", "123", IdentityType.CADC.getValue());

        checkPath("/groupName/groupMembers/memberGroup", "groupName", "memberGroup", null);
    }

    private void checkPath(String path, String expectedGroupName, String expectedMemberName, String expectedUserIDType) {
        abstractAction.setSyncInput(new SyncInput() {
            @Override
            public String getPath() {
                return path.split("\\?")[0];
            }

            @Override
            public String getParameter(String name) {
                if (path.contains("?")) {
                    return path.split("\\?")[1].split("idType=")[1];
                }
                return null;
            }
        });
        abstractAction.setRequestInput();
        AbstractAction.RequestInput requestInput = abstractAction.requestInput;
        assertEquals(expectedGroupName, requestInput.groupName);
        assertEquals(expectedMemberName, requestInput.memberName);
        assertEquals(expectedUserIDType, requestInput.userIDType);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSetRequestInputInvalidPath() {
        abstractAction.setSyncInput(new SyncInput() {
            @Override
            public String getPath() {
                return "/invalid/path/with/too/many/segments";
            }

            @Override
            public String getParameter(String name) {
                return null;
            }
        });

        abstractAction.setRequestInput();
    }
}
