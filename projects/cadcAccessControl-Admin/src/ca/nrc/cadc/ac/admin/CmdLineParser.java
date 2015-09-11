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

 package ca.nrc.cadc.ac.admin;

import java.io.PrintStream;
import java.security.cert.CertificateException;

import javax.security.auth.Subject;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import ca.nrc.cadc.auth.CertCmdArgUtil;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.util.ArgumentMap;
import ca.nrc.cadc.util.Log4jInit;
import ca.nrc.cadc.util.StringUtil;



/**
 * This class parses the command line input arguments.
 */
public class CmdLineParser 
{
    private static Logger log = Logger.getLogger(CmdLineParser.class);
    private static final String APP_NAME = "userAdmin";
    private static final String[] LOG_PACKAGES = 
		{"ca.nrc.cadc.ac", "ca.nrc.cadc.auth", "ca.nrc.cadc.util"};

    // no need to proceed further if false
    private Level logLevel = Level.OFF;
    private boolean proceed = true;
    private AbstractCommand command;
    private Subject subject;

    /**
     * Constructor.
     * @param args Input arguments
     * @throws UsageException Error in command line
     * @throws CertificateException Fail to get a certificate
     */
    public CmdLineParser(final String[] args, final PrintStream outStream,
        final PrintStream errStream) throws UsageException, CertificateException 
    {
        ArgumentMap am = new ArgumentMap( args );
    	this.setLogLevel(am);
    	this.parse(am, outStream, errStream);
    }
    
    /**
     * Return proceed status.
     * @return true  program should proceed with further processing
     *         false program should not proceed further
     */
    public boolean proceed()
    {
        return this.proceed;
    }

    /**
     * Get the user admin command to be performed.
     * @return user admin command
     */
    public AbstractCommand getCommand()
    {
    	return this.command;
    }
    
    /**
     * Get the subject representing the user executing this user admin tool.
     */
    public Subject getSubject()
    {
    	return this.subject;
    }
    
    /**
     * Get the logging level.
     */
    public Level getLogLevel()
    {
    	return this.logLevel;
    }

    /*
     * Set the log level.
     * @param am Input arguments
     * @throws UsageException 
     */
    protected void setLogLevel(final ArgumentMap am) throws UsageException
    {
    	int count = 0;
    	
        // only one log level is allowed 
    	if (am.isSet("v") || am.isSet("verbose"))
    	{
            this.logLevel = Level.INFO;
            count++;
    	}

    	if (am.isSet("d") || am.isSet("debug"))
    	{
            this.logLevel = Level.DEBUG;
            count++;
    	}
                    	
    	if (count >=2)
    	{
            String msg = "--verbose and --debug are mutually exclusive options";            
            throw new UsageException(msg);
    	}
    	else
    	{        	
            // set the application log level
            for (String pkg : LOG_PACKAGES)
            {
                Log4jInit.setLevel(APP_NAME, pkg, this.logLevel);
            }
    	}
    }
    
    protected boolean hasValue(final String userID) throws UsageException
    {
        if (!StringUtil.hasText(userID) ||userID.equalsIgnoreCase("true"))
        {
            String msg = "Missing userID";
            throw new UsageException(msg);
        }
        else
        {
            return true;
        }
    }
    
    protected boolean isValid(final ArgumentMap am, final PrintStream outStream,
        final PrintStream errStream) throws UsageException
    {
    	int count = 0;
    	
        // only one command is allowed per command line
    	if (am.isSet("list"))
    	{
            this.command = new ListActiveUsers();
            count++;
    	}

    	if (am.isSet("list-pending"))
    	{
            this.command = new ListPendingUsers();
            count++;
    	}
    	
    	String userID = am.getValue("view");
    	if (userID != null	)
    	{
            if (this.hasValue(userID))
    	    {
                this.command = new ViewUser(userID);
    	    }
    		
            count++;
    	}
    	
        userID = am.getValue("reject");
    	if (userID != null	)
    	{
            if (this.hasValue(userID))
    	    {
                this.command = new RejectUser(userID);
    	    }
    		
            count++;
    	}
    	
        userID = am.getValue("approve");
    	if (userID != null	)
    	{
            if (this.hasValue(userID))
    	    {
                this.command = new ApproveUser(userID);
    	    }
    		
            count++;
    	}
                    	
    	if (count == 1)
    	{
            this.command.setSystemOut(outStream);
            this.command.setSystemErr(errStream);
            return true;
    	}
    	else
    	{
            String msg;
    		
            if (count == 0)
            {
                msg = "Missing command or ommand is not supported.";
            }
            else
            {
                msg = "Only one command can be specified.";
            }
    	
            throw new UsageException(msg);
    	}
    }
    
    /*
     * Parse the command line arguments.
     * @param ArgumentMap Command line arguments
     * @throws UsageException Error in command line
     * @throws CertificateException Fail to get a certificate
     */
    protected void parse(final ArgumentMap am, final PrintStream out,
        final PrintStream err) throws UsageException, CertificateException
    {
        this.proceed = false;

        if (!am.isSet("h") && !am.isSet("help") && isValid(am, out, err))
        {
            Subject subject = CertCmdArgUtil.initSubject(am, true);
            
            try 
            {
                SSLUtil.validateSubject(subject, null);
                this.subject = subject;
                this.proceed = true;
            } 
            catch (CertificateException e) 
            {
            	if (am.isSet("list"))
            	{
                    // we can use anonymous subject
                    this.proceed = true;
            	}
            	else
            	{
                    throw e;
            	}
            }
        }
    }    

    /**
     * Provide the default command line usage. 
     */
    public static String getUsage()
    {
    	StringBuilder sb = new StringBuilder();
    	sb.append("\n");
    	sb.append("Usage: " + APP_NAME + " [--cert=<path to pem file>] <command> [-v|--verbose|-d|--debug] [-h|--help]\n");
    	sb.append("Where command is\n");
    	sb.append("--list               :list users in the Users tree\n");
    	sb.append("                     :can be executed as an anonymous user\n");
    	sb.append("--list-pending       :list users in the UserRequests tree\n");
    	sb.append("                     :except those with nsaccountlock=true\n");
    	sb.append("                     :can be executed as an anonymous user\n");
    	sb.append("--view=<userid>      :print the entire details of the user\n");
    	sb.append("--approve=<userid>   :delete the user from the UserRequests tree\n");
    	sb.append("                     :by setting nsaccount=true, and insert it to the Users tree\n");
    	sb.append("--reject=<userid>    :delete the user from the UserRequests tree\n");
    	sb.append("\n");
    	sb.append("-v|--verbose         : Verbose mode print progress and error messages\n");
    	sb.append("-d|--debug           : Debug mode print all the logging messages\n");
    	sb.append("-h|--help            : Print this message and exit\n");
    	return sb.toString();
    }
}
