/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2009.                            (c) 2009.
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

package ca.nrc.cadc.ac.admin;

import java.io.PrintStream;

import org.apache.log4j.Level;
import org.junit.Assert;
import org.junit.Test;


/**
 * 
 */
public class CmdLineParserTest
{    
    private static PrintStream sysOut = System.out;
    private static PrintStream sysErr = System.err;

    @Test
	public void testHelp()
	{
		// case 1: short form
    	try
    	{
    	    String[] mArgs = {"-h"};
    	    CmdLineParser parser = new CmdLineParser(mArgs, sysOut, sysErr);
    	    Assert.assertEquals(Level.OFF, parser.getLogLevel());
    	}
    	catch (Exception e)
    	{
    	    Assert.fail("Caught an unexpected exception, " + e.getMessage());
    	}
    	
		// case 2: long form
    	try
    	{
    	    String[] mArgs = {"--help"};
    	    CmdLineParser parser = new CmdLineParser(mArgs, sysOut, sysErr);
    	    Assert.assertEquals(Level.OFF, parser.getLogLevel());
    	}
    	catch (Exception e)
    	{
    	    Assert.fail("Caught an unexpected exception, " + e.getMessage());
    	}

		// case 3: mixed with a command
    	try
    	{
    	    String[] mArgs = {"--list", "-h"};
    	    CmdLineParser parser = new CmdLineParser(mArgs, sysOut, sysErr);
    	    Assert.assertEquals(Level.OFF, parser.getLogLevel());
    	}
    	catch (Exception e)
    	{
    	    Assert.fail("Caught an unexpected exception, " + e.getMessage());
    	}

		// case 4: mixed with a command and log level
    	try
    	{
    	    String[] mArgs = {"--list", "-h", "-v"};
    	    CmdLineParser parser = new CmdLineParser(mArgs, sysOut, sysErr);
    	    Assert.assertEquals(Level.INFO, parser.getLogLevel());
    	}
    	catch (Exception e)
    	{
    	    Assert.fail("Caught an unexpected exception, " + e.getMessage());
    	}
	}
	
    @Test
    public void testSetLogLevel()
    {
    	// case 1: no level
    	try
    	{
    	    String[] args = {"--list",};
    	    CmdLineParser parser = new CmdLineParser(args, sysOut, sysErr);
    	    Assert.assertEquals(Level.OFF, parser.getLogLevel());
    	}
    	catch (Exception e)
    	{
    	    Assert.fail("Caught an unexpected exception, " + e.getMessage());
    	}
    	
    	// case 2: verbose level
    	try
    	{
    	    String[] vArgs = {"--list", "-v"};
    	    CmdLineParser parser = new CmdLineParser(vArgs, sysOut, sysErr);
    	    Assert.assertEquals(Level.INFO, parser.getLogLevel());
    	}
    	catch (Exception e)
    	{
    	    Assert.fail("Caught an unexpected exception, " + e.getMessage());
    	}
    	
    	// case 3: debug level
    	try
    	{
    	    String[] dArgs = {"--list", "-d"};
    	    CmdLineParser parser = new CmdLineParser(dArgs, sysOut, sysErr);
    	    Assert.assertEquals(Level.DEBUG, parser.getLogLevel());
    	}
    	catch (Exception e)
    	{
    	    Assert.fail("Caught an unexpected exception, " + e.getMessage());
    	}
    	
    	// case 4: debug level
    	CmdLineParser parser = null;
    	
    	try
    	{
    	    String[] mArgs = {"--list", "-d", "-v"};
    	    parser = new CmdLineParser(mArgs, sysOut, sysErr);
    	    Assert.fail("Should have received a UsageException.");
    	}
    	catch (UsageException e)
    	{
            String expected = "--verbose and --debug are mutually exclusive options";
            Assert.assertTrue(e.getMessage().contains(expected));
    	}
    	catch (Exception e)
    	{
    	    Assert.fail("Caught an unexpected exception, " + e.getMessage());
    	}
    	
    	Assert.assertNull(parser);
    }
    
    @Test
    public void testCommandValidation()
    {
    	// case 1: no command
    	try
    	{
    	    String[] dArgs = {"-d"};
    	    new CmdLineParser(dArgs, sysOut, sysErr);
    	    Assert.fail("Should have received a UsageException.");
    	}
    	catch (UsageException e)
    	{
            String expected = "Missing command or ommand is not supported";
            Assert.assertTrue(e.getMessage().contains(expected));
    	}
    	catch (Exception e)
    	{
    	    Assert.fail("Caught an unexpected exception, " + e.getMessage());
    	}
    	
    	// case 2: one --list command
    	try
    	{
    	    String[] dArgs = {"--list", "-d"};
    	    CmdLineParser parser = new CmdLineParser(dArgs, sysOut, sysErr);
    	    Assert.assertEquals(Level.DEBUG, parser.getLogLevel());
    	    Assert.assertTrue(parser.getCommand() instanceof ListActiveUsers);
    	}
    	catch (Exception e)
    	{
    	    Assert.fail("Caught an unexpected exception, " + e.getMessage());
    	}
    	
    	// case 3: one --list-pending command
    	try
    	{
    	    String[] dArgs = {"--list-pending", "-d"};
    	    CmdLineParser parser = new CmdLineParser(dArgs, sysOut, sysErr);
    	    Assert.assertEquals(Level.DEBUG, parser.getLogLevel());
    	    Assert.assertTrue(parser.getCommand() instanceof ListPendingUsers);
    	}
    	catch (Exception e)
    	{
    	    Assert.fail("Caught an unexpected exception, " + e.getMessage());
    	}
    	
    	// case 4: one --view command
    	try
    	{
    	    String[] dArgs = {"--view=jdoe", "-d"};
    	    CmdLineParser parser = new CmdLineParser(dArgs, sysOut, sysErr);
    	    Assert.assertEquals(Level.DEBUG, parser.getLogLevel());
    	    Assert.assertTrue(parser.getCommand() instanceof ViewUser);
    	}
    	catch (Exception e)
    	{
    	    Assert.fail("Caught an unexpected exception, " + e.getMessage());
    	}
    	
    	// case 5: one --reject command
    	try
    	{
    	    String[] dArgs = {"--reject=jdoe", "-d"};
    	    CmdLineParser parser = new CmdLineParser(dArgs, sysOut, sysErr);
    	    Assert.assertEquals(Level.DEBUG, parser.getLogLevel());
    	    Assert.assertTrue(parser.getCommand() instanceof RejectUser);
    	}
    	catch (Exception e)
    	{
    	    Assert.fail("Caught an unexpected exception, " + e.getMessage());
    	}
    	
    	// case 6: one --approve command
    	try
    	{
    	    String[] dArgs = {"--approve=jdoe", "-d"};
    	    CmdLineParser parser = new CmdLineParser(dArgs, sysOut, sysErr);
    	    Assert.assertEquals(Level.DEBUG, parser.getLogLevel());
    	    Assert.assertTrue(parser.getCommand() instanceof ApproveUser);
    	}
    	catch (Exception e)
    	{
    	    Assert.fail("Caught an unexpected exception, " + e.getMessage());
    	}
    	
    	// case 7: one command with no user ID
    	try
    	{
    	    String[] dArgs = {"--approve", "-d"};
    	    new CmdLineParser(dArgs, sysOut, sysErr);
    	    Assert.fail("Should have received a UsageException.");
    	}
    	catch (UsageException e)
    	{
            String expected = "Missing userID";
            Assert.assertTrue(e.getMessage().contains(expected));
    	}
    	catch (Exception e)
    	{
    	    Assert.fail("Caught an unexpected exception, " + e.getMessage());
    	}
    	
    	// case 8: one command with no user ID
    	try
    	{
    	    String[] dArgs = {"--approve=", "-d"};
    	    new CmdLineParser(dArgs, sysOut, sysErr);
    	    Assert.fail("Should have received a UsageException.");
    	}
    	catch (UsageException e)
    	{
            String expected = "Missing userID";
            Assert.assertTrue(e.getMessage().contains(expected));
    	}
    	catch (Exception e)
    	{
    	    Assert.fail("Caught an unexpected exception, " + e.getMessage());
    	}
    	
    	// case 8: more than one command
    	try
    	{
    	    String[] dArgs = {"--list", "--list-pending", "-d"};
    	    new CmdLineParser(dArgs, sysOut, sysErr);
    	    Assert.fail("Should have received a UsageException.");
    	}
    	catch (UsageException e)
    	{
            String expected = "Only one command can be specified";
            Assert.assertTrue(e.getMessage().contains(expected));
    	}
    	catch (Exception e)
    	{
    	    Assert.fail("Caught an unexpected exception, " + e.getMessage());
    	}

    }
}
