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
package ca.nrc.cadc.ac.server.web.users;

import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.UserRequest;
import ca.nrc.cadc.ac.server.PluginFactory;
import ca.nrc.cadc.ac.server.UserPersistence;
import ca.nrc.cadc.net.TransientException;
import org.apache.log4j.Logger;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.security.AccessControlException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Map;

public abstract class UsersAction
    implements PrivilegedExceptionAction<Object>
{
    private static final Logger log = Logger.getLogger(UsersAction.class);
    static final String DEFAULT_CONTENT_TYPE = "text/xml";
    static final String JSON_CONTENT_TYPE = "application/json";

    protected UserLogInfo logInfo;
    protected HttpServletResponse response;
    protected String acceptedContentType = DEFAULT_CONTENT_TYPE;

    private String redirectURLPrefix;


    UsersAction(UserLogInfo logInfo)
    {
        this.logInfo = logInfo;
    }

    public void doAction(Subject subject, HttpServletResponse response)
        throws IOException
    {
        try
        {
            try
            {
                this.response = response;

                if (subject == null)
                {
                    run();
                }
                else
                {
                    Subject.doAs(subject, this);
                }
            }
            catch (PrivilegedActionException e)
            {
                Throwable cause = e.getCause();
                if (cause != null)
                {
                    throw cause;
                }
                throw e;
            }
        }
        catch (AccessControlException e)
        {
            log.debug(e.getMessage(), e);
            String message = "Permission Denied";
            this.logInfo.setMessage(message);
            sendError(403, message);
        }
        catch (IllegalArgumentException e)
        {
            log.debug(e.getMessage(), e);
            String message = e.getMessage();
            this.logInfo.setMessage(message);
            sendError(400, message);
        }
        catch (UserNotFoundException e)
        {
            log.debug(e.getMessage(), e);
            String message = "User not found: " + e.getMessage();
            this.logInfo.setMessage(message);
            sendError(404, message);
        }
        catch (UnsupportedOperationException e)
        {
            log.debug(e.getMessage(), e);
            this.logInfo.setMessage("Not yet implemented.");
            sendError(501);
        }
        catch (TransientException e)
        {
            String message = "Internal Transient Error: " + e.getMessage();
            this.logInfo.setSuccess(false);
            this.logInfo.setMessage(message);
            log.error(message, e);
            sendError(503, message);
        }
        catch (Throwable t)
        {
            String message = "Internal Error: " + t.getMessage();
            this.logInfo.setSuccess(false);
            this.logInfo.setMessage(message);
            log.error(message, t);
            sendError(500, message);
        }
    }

    private void sendError(int responseCode)
        throws IOException
    {
        sendError(responseCode, null);
    }

    private void sendError(int responseCode, String message)
        throws IOException
    {
        if (!this.response.isCommitted())
        {
            this.response.setContentType("text/plain");
            if (message != null)
            {
                this.response.getWriter().write(message);
            }
            this.response.setStatus(responseCode);
        }
        else
        {
            log.warn("Could not send error " + responseCode + " (" + message + ") because the response is already committed.");
        }
    }

    @SuppressWarnings("unchecked")
    <T extends Principal> UserPersistence<T> getUserPersistence()
    {
        PluginFactory pluginFactory = new PluginFactory();
        return pluginFactory.getUserPersistence();
    }

    protected void logUserInfo(String userName)
    {
        this.logInfo.userName = userName;
    }

    public void setAcceptedContentType(final String acceptedContentType)
    {
        this.acceptedContentType = acceptedContentType;
    }

    /**
     * Read a user request (User pending approval) from the HTTP Request's
     * stream.
     *
     * @param inputStream           The Input Stream to read from.
     * @return                      User Request instance.
     * @throws IOException          Any reading errors.
     */
    protected final UserRequest<Principal> readUserRequest(
            final InputStream inputStream) throws IOException
    {
        final UserRequest<Principal> userRequest;

        if (acceptedContentType.equals(DEFAULT_CONTENT_TYPE))
        {
            userRequest = ca.nrc.cadc.ac.xml.UserRequestReader.read(inputStream);
        }
        else if (acceptedContentType.equals(JSON_CONTENT_TYPE))
        {
            userRequest =
                    ca.nrc.cadc.ac.json.UserRequestReader.read(inputStream);
        }
        else
        {
            // Should never happen.
            throw new IOException("Unknown content being asked for: "
                                  + acceptedContentType);
        }

        return userRequest;
    }

    /**
     * Read the user from the given stream of marshalled data.
     *
     * @param inputStream       The stream to read in.
     * @return                  User instance, never null.
     *
     * @throws IOException      Any errors in reading the stream.
     */
    protected final User<Principal> readUser(final InputStream inputStream)
            throws IOException
    {
        response.setContentType(acceptedContentType);
        final User<Principal> user;

        if (acceptedContentType.equals(DEFAULT_CONTENT_TYPE))
        {
            user = ca.nrc.cadc.ac.xml.UserReader.read(inputStream);
        }
        else if (acceptedContentType.equals(JSON_CONTENT_TYPE))
        {
            user = ca.nrc.cadc.ac.json.UserReader.read(inputStream);
        }
        else
        {
            // Should never happen.
            throw new IOException("Unknown content being asked for: "
                                  + acceptedContentType);
        }

        return user;
    }

    /**
     * Write a user to the response's writer.
     *
     * @param user              The user object to marshall and write out.
     * @throws IOException      Any writing errors.
     */
    protected final <T extends Principal> void writeUser(final User<T> user)
            throws IOException
    {
        response.setContentType(acceptedContentType);
        final Writer writer = response.getWriter();

        if (acceptedContentType.equals(DEFAULT_CONTENT_TYPE))
        {
            ca.nrc.cadc.ac.xml.UserWriter.write(user, writer);
        }
        else if (acceptedContentType.equals(JSON_CONTENT_TYPE))
        {
            ca.nrc.cadc.ac.json.UserWriter.write(user, writer);
        }
    }

    /**
     * Write out a Map of users as this Action's specified content type.
     *
     * @param users         The Map of user IDs to names.
     */
    protected final void writeUsers(final Map<String, PersonalDetails> users)
            throws IOException
    {
        response.setContentType(acceptedContentType);
        final Writer writer = response.getWriter();

        if (acceptedContentType.equals(DEFAULT_CONTENT_TYPE))
        {
            ca.nrc.cadc.ac.xml.UsersWriter.write(users, writer);
        }
        else if (acceptedContentType.equals(JSON_CONTENT_TYPE))
        {
            ca.nrc.cadc.ac.json.UsersWriter.write(users, writer);
        }
    }

    protected void setRedirectURLPrefix(final String redirectURLPrefix)
    {
        this.redirectURLPrefix = redirectURLPrefix;
    }

    void redirectGet(final String userID) throws Exception
    {
        final String redirectURL = this.redirectURLPrefix + "/" + userID
                                   + "?idType=HTTP";
        response.setHeader("Location", redirectURL);
    }
}
