/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2021.                            (c) 2021.
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
    private AbstractCommand command;
    private boolean isHelpCommand = false;
    private ArgumentMap am;

    /**
     * Constructor.
     * @param args Input arguments
     * @throws UsageException Error in command line
     * @throws CertificateException Fail to get a certificate
     */
    public CmdLineParser(final String[] args, final PrintStream outStream,
        final PrintStream errStream) throws UsageException, CertificateException
    {
        am = new ArgumentMap( args );
    	this.setLogLevel(am);
    	this.parse(am, outStream, errStream);
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
     * Get the logging level.
     */
    public Level getLogLevel()
    {
    	return this.logLevel;
    }

    public Subject getSubjectFromCert()
    {
        return CertCmdArgUtil.initSubject(am);
    }

    /*
     * Set the log level.
     * @param am Input arguments
     * @throws UsageException
     */
    protected void setLogLevel(final ArgumentMap am) throws UsageException
    {
    	int count = 0;

    	this.logLevel = Level.WARN;

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

    protected boolean isValid(final ArgumentMap am) throws UsageException
    {
    	int count = 0;

        // only one command is allowed per command line
    	if (am.isSet("list"))
    	{
    	    if (am.isSet("email")) {
    	        this.command = new ListUsers(am.getValue("email"));
    	    } else {
    	        this.command = new ListUsers();
    	    }
            count++;
    	}

    	if (am.isSet("list-pending"))
    	{
            this.command = new ListUserRequests();
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
    	
    	userID = am.getValue("set");
        if (userID != null)
        {
            String email = am.getValue("email");
            if (email != null)
            {
                this.command = new ModifyUser(userID, email);
            }
            else
            {
                throw new UsageException("Missing parameter 'email'");
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
                String dn = am.getValue("dn");
                if (dn != null)
                {
                    this.command = new ApproveUser(userID, dn);
                }
                else
                {
                    throw new UsageException("Missing parameter 'dn'");
                }
    	    }

            count++;
    	}

        userID = am.getValue("disable");
        if (userID != null)
        {
            if (this.hasValue(userID))
            {
                this.command = new DisableUser(userID);
            }

            count++;
        }

        userID = am.getValue("enable");
        if (userID != null)
        {
            if (this.hasValue(userID))
            {
                this.command = new EnableUser(userID);
            }

            count++;
        }

    	if (count == 1)
    	{
            return true;
    	}
    	else
    	{
            String msg;

            if (count == 0)
            {
                msg = "Missing command or command is not supported.";
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

        if (!am.isSet("h") && !am.isSet("help") && isValid(am))
        {
            // the following statements are executed only when proceed is true
            this.command.setSystemOut(out);
            this.command.setSystemErr(err);
        }
        else
        {
            isHelpCommand = true;
        }
    }

    public boolean isHelpCommand()
    {
        return isHelpCommand;
    }

    /**
     * Provide the default command line usage.
     */
    public static String getUsage()
    {
    	StringBuilder sb = new StringBuilder();
    	sb.append("\n");
    	sb.append("Usage: " + APP_NAME + " <command> [-v|--verbose|-d|--debug] [-h|--help]\n");
    	sb.append(CertCmdArgUtil.getCertArgUsage());
    	sb.append("\n");
    	sb.append("Where command is\n");
    	sb.append("--list                         : List users in the Users tree\n");
        sb.append("--list --email=<email>         : List users with email address <email>\n");
    	sb.append("--list-pending                 : List users in the UserRequests tree\n");
    	sb.append("--view=<userid>                : Print the entire details of the user\n");
    	sb.append("--set=<userid> --email=<email> : Set the email address to <email> for user <userid>\n");
    	sb.append("--approve=<userid> --dn=<dn>   : Approve user with userid=<userid> and set the\n");
    	sb.append("                               : distinguished name to <dn>\n");
    	sb.append("--reject=<userid>              : Delete this user request\n");
        sb.append("--enable=<userid>              : Enable this user account\n");
        sb.append("--disable=<userid>             : Disable this user account\n");
    	sb.append("\n");
    	sb.append("-v|--verbose                   : Verbose mode print progress and error messages\n");
    	sb.append("-d|--debug                     : Debug mode print all the logging messages\n");
    	sb.append("-h|--help                      : Print this message and exit\n");
    	sb.append("\n");
        sb.append("Authentication and authorization:\n");
        sb.append("  - An ac-ldap-config.properties file must exist in directory ~/config/\n");
        sb.append("  - The corresponding host entry (devLdap or prodLdap) must exist\n");
        sb.append("    in your ~/.dbrc file.");

    	return sb.toString();
    }
}
