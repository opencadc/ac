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
package ca.nrc.cadc.ac.server;

import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.server.web.groups.AddUserMemberActionTest;
import ca.nrc.cadc.auth.IdentityType;
import ca.nrc.cadc.util.Log4jInit;
import ca.nrc.cadc.uws.Parameter;

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 *
 * @author jburke
 */
public class RequestValidatorTest
{
    private final static Logger log = Logger.getLogger(AddUserMemberActionTest.class);

    @BeforeClass
    public static void setUpClass()
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
    }

    /**
     * Test of validate method, of class RequestValidator.
     */
    @Test
    public void testValidate()
    {
        try
        {
            RequestValidator rv = new RequestValidator();

            try
            {
                rv.validate(null);
                fail("null parameter list should throw IllegalArgumentException");
            }
            catch (IllegalArgumentException ignore) {}

            List<Parameter> paramList = new ArrayList<Parameter>();
            try
            {
                rv.validate(paramList);
                fail("empty parameter list should throw IllegalArgumentException");
            }
            catch (IllegalArgumentException ignore) {}

            paramList.add(new Parameter("IDTYPE", "idtype"));
            paramList.add(new Parameter("ROLE", "role"));
            try
            {
                rv.validate(paramList);
                fail("missing ID parameter should throw IllegalArgumentException");
            }
            catch (IllegalArgumentException ignore) {}

            paramList.clear();
            paramList.add(new Parameter("ID", "foo"));
            paramList.add(new Parameter("ROLE", "role"));
            try
            {
                rv.validate(paramList);
                fail("missing IDTYPE parameter should throw IllegalArgumentException");
            }
            catch (IllegalArgumentException ignore) {}

            paramList.clear();
            paramList.add(new Parameter("ID", "foo"));
            paramList.add(new Parameter("IDTYPE", "idtype"));
            try
            {
                rv.validate(paramList);
                fail("missing ROLE parameter should throw IllegalArgumentException");
            }
            catch (IllegalArgumentException ignore) {}

            paramList.clear();
            paramList.add(new Parameter("ID", "foo"));
            paramList.add(new Parameter("IDTYPE", IdentityType.USERNAME.getValue()));
            paramList.add(new Parameter("ROLE", "foo"));
            try
            {
                rv.validate(paramList);
                fail("invalid ROLE parameter should throw IllegalArgumentException");
            }
            catch (IllegalArgumentException ignore) {}

            paramList.clear();
            paramList.add(new Parameter("ID", "foo"));
            paramList.add(new Parameter("IDTYPE", IdentityType.USERNAME.getValue()));
            paramList.add(new Parameter("ROLE", "foo"));
            paramList.add(new Parameter("GROUPID", ""));
            try
            {
                rv.validate(paramList);
                fail("empty GROUPID parameter value should throw IllegalArgumentException");
            }
            catch (IllegalArgumentException ignore) {}

            paramList.clear();
            paramList.add(new Parameter("ID", "foo"));
            paramList.add(new Parameter("IDTYPE", IdentityType.USERNAME.getValue()));
            paramList.add(new Parameter("ROLE", Role.MEMBER.getValue()));
            rv.validate(paramList);

            assertNotNull(rv.getPrincipal());
            assertNotNull(rv.getRole());
            assertNull(rv.getGroupID());

            paramList.add(new Parameter("GROUPID", "bar"));
            rv.validate(paramList);

            assertNotNull(rv.getPrincipal());
            assertNotNull(rv.getRole());
            assertNotNull(rv.getGroupID());
        }
        catch (Throwable t)
        {
            log.error(t.getMessage(), t);
            fail("unexpected error: " + t.getMessage());
        }
    }

}
