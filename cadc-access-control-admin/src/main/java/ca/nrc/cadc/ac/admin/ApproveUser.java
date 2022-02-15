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

import java.security.AccessControlException;
import java.util.IllegalFormatException;

import java.util.List;
import java.util.PropertyResourceBundle;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.net.TransientException;

/**
 * This class approves the specified pending user by moving the user
 * from a pending user to an active user in the LDAP server.
 * @author yeunga
 *
 */
public class ApproveUser extends AbstractUserCommand
{
    private static final Logger log = Logger.getLogger(ApproveUser.class);

    private static final List<String> MAIL_PROPS =
        Stream.of(Mailer.MAIL_FROM, Mailer.MAIL_REPLY_TO, Mailer.MAIL_SUBJECT, Mailer.MAIL_BODY,
                  Mailer.SMTP_AUTH_HOST, Mailer.SMTP_AUTH_PORT, Mailer.SMTP_ACCOUNT, Mailer.SMTP_PASSWORD)
            .collect(Collectors.toList());

    private final String dn;
    private final PropertyResourceBundle mailProps;

    /**
     * Constructor
     * @param userID Id of the pending user to be approved
     */
    public ApproveUser(final String userID, final String dn)
        throws UsageException
    {
    	super(userID);
    	this.dn = dn;
        this.mailProps = AdminUtil.getProperties(Mailer.MAIL_CONFIG, MAIL_PROPS);
    }

    protected void execute()
	    throws AccessControlException, UserNotFoundException, TransientException
    {
        X500Principal dnPrincipal = null;
        try
        {
            dnPrincipal = new X500Principal(dn);
        }
        catch (Exception e)
        {
            throw new IllegalArgumentException("Invalid DN format: " + dn);
        }

        try
        {
            this.getUserPersistence().approveUserRequest(this.getPrincipal());
            this.systemOut.println("User " + this.getPrincipal().getName() + " was approved successfully.");
        }
        catch (UserNotFoundException e)
        {
            this.systemOut.println("Could not find userRequest " + this.getPrincipal());
            return;
        }

        User user = null;
        try
        {
            user = this.getUserPersistence().getUser(this.getPrincipal());
        }
        catch (UserNotFoundException e)
        {
            this.systemOut.println("Could not set user DN");
            return;
        }

        // email the user
        emailUser(user);

        user.getIdentities().add(dnPrincipal);
        this.getUserPersistence().modifyUser(user);
        String noWhiteSpaceDN = dn.replaceAll("\\s","");
        this.systemOut.println("User " + this.getPrincipal().getName() + " now has DN " + noWhiteSpaceDN);
        this.printUser(user);
    }

    private void emailUser(User  user)
    {
        try
        {
            String recipient = null;
            if (user.personalDetails != null)
            {
                recipient = user.personalDetails.email;
            }
            if (recipient == null)
            {
                log.warn("No user email address, not emailing");
                return;
            }

            // try to put the userid in the body
            String populatedBody = null;
            String body = mailProps.getString(Mailer.MAIL_BODY);
            HttpPrincipal p = user.getIdentities(HttpPrincipal.class).iterator().next();
            try
            {
                populatedBody = String.format(body, p.getName());
            }
            catch (IllegalFormatException e)
            {
                log.info("userid not inserted into message body");
            }

            if (populatedBody == null)
            {
                populatedBody = body;
            }
            log.debug("email body populated: " + populatedBody);

            Mailer mailer = new Mailer();
            mailer.setSmtpHost(this.mailProps.getString(Mailer.SMTP_AUTH_HOST));
            mailer.setSmtpPort(this.mailProps.getString(Mailer.SMTP_AUTH_PORT));
            mailer.setSmtpAccount(this.mailProps.getString(Mailer.SMTP_ACCOUNT));
            mailer.setSmtpPassword(this.mailProps.getString(Mailer.SMTP_PASSWORD));

            mailer.setToList(new String[] { recipient });
            mailer.setReplyToList(new String[] { mailProps.getString(Mailer.MAIL_REPLY_TO)});
            mailer.setFrom(mailProps.getString(Mailer.MAIL_FROM));
            mailer.setSubject(mailProps.getString(Mailer.MAIL_SUBJECT));
            mailer.setBody(populatedBody);

            if (mailProps.containsKey(Mailer.MAIL_BCC)) {
                mailer.setBccList(new String[] { mailProps.getString(Mailer.MAIL_BCC) });
            }

            mailer.setContentType(Mailer.HTML_CONTENT_TYPE);

            boolean authenticated = true;
            mailer.doSend(authenticated);
            this.systemOut.println("Emailed approval message to user.");
        }
        catch (Exception e)
        {
            this.systemOut.println("Failed to email user");
            log.warn("Failed to email user", e);
        }
    }
}
