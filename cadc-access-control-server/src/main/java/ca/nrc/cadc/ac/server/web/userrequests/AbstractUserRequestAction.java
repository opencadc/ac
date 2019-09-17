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
package ca.nrc.cadc.ac.server.web.userrequests;

import ca.nrc.cadc.ac.ReaderException;
import ca.nrc.cadc.ac.UserAlreadyExistsException;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.UserRequest;
import ca.nrc.cadc.ac.json.JsonUserRequestReader;
import ca.nrc.cadc.ac.server.UserPersistence;
import ca.nrc.cadc.ac.server.web.SyncOutput;
import ca.nrc.cadc.ac.server.web.users.UserLogInfo;
import ca.nrc.cadc.ac.xml.UserRequestReader;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.profiler.Profiler;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.security.AccessControlException;
import java.security.Principal;
import java.security.PrivilegedExceptionAction;

public abstract class AbstractUserRequestAction implements PrivilegedExceptionAction<Object>
{
    private static final Logger log = Logger.getLogger(AbstractUserRequestAction.class);
    public static final String DEFAULT_CONTENT_TYPE = "text/xml";
    public static final String JSON_CONTENT_TYPE = "application/json";
    private Profiler profiler = new Profiler(AbstractUserRequestAction.class);

    protected boolean isAugmentUser;
    protected UserLogInfo logInfo;
    protected SyncOutput syncOut;
    protected UserPersistence userPersistence;
    protected Principal groupOwnerHttpPrincipal;

    protected String acceptedContentType = DEFAULT_CONTENT_TYPE;

    AbstractUserRequestAction()
    {
        this.isAugmentUser = false;
    }

    public abstract void doAction() throws Exception;

    public void setAugmentUser(final boolean isAugmentUser)
    {
    	this.isAugmentUser = isAugmentUser;
    }

    public boolean isAugmentUser()
    {
    	return this.isAugmentUser;
    }

    public void setLogInfo(UserLogInfo logInfo)
    {
        this.logInfo = logInfo;
    }

    public void setSyncOut(SyncOutput syncOut)
    {
        this.syncOut = syncOut;
    }

    public void setUserPersistence(UserPersistence userPersistence)
    {
        this.userPersistence = userPersistence;
    }

    public Object run() throws IOException
    {
        try
        {
            doAction();
            profiler.checkpoint("doAction");
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
        catch (ReaderException e)
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
        catch (UserAlreadyExistsException e)
        {
            log.debug(e.getMessage(), e);
            String message = e.getMessage();
            this.logInfo.setMessage(message);
            sendError(409, message);
        }
        catch (UnsupportedOperationException e)
        {
            log.debug(e.getMessage(), e);
            this.logInfo.setMessage("Not yet implemented.");
            sendError(501);
        }
        catch (TransientException e)
        {
            String message = "Transient Error: " + e.getMessage();
            this.logInfo.setSuccess(false);
            this.logInfo.setMessage(message);
            if (e.getRetryDelay() > 0)
                syncOut.setHeader("Retry-After", Integer.toString(e.getRetryDelay()));
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
        return null;
    }

    private void sendError(int responseCode)
        throws IOException
    {
        sendError(responseCode, null);
    }

    private void sendError(int responseCode, String message)
    {
        syncOut.setCode(responseCode);
        syncOut.setHeader("Content-Type", "text/plain");
        if (message != null)
        {
            try
            {
                syncOut.getWriter().write(message);
            }
            catch (IOException e)
            {
                log.warn("Could not write error message to output stream");
            }
        }
        profiler.checkpoint("sendError");
    }

    protected void logUserInfo(String userName)
    {
        this.logInfo.userName = userName;
    }

    public void setPosixGroupOwnerHttpPrincipal(final Principal groupOwnerHttpPrincipal)
    {
        this.groupOwnerHttpPrincipal = groupOwnerHttpPrincipal;
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
    protected UserRequest readUserRequest(final InputStream inputStream)
        throws ReaderException, IOException
    {
        final UserRequest userRequest;

        if (acceptedContentType.equals(DEFAULT_CONTENT_TYPE))
        {
            UserRequestReader requestReader = new UserRequestReader();
            userRequest = requestReader.read(inputStream);
        }
        else if (acceptedContentType.equals(JSON_CONTENT_TYPE))
        {
            JsonUserRequestReader requestReader = new JsonUserRequestReader();
            userRequest = requestReader.read(inputStream);
        }
        else
        {
            // Should never happen.
            throw new IOException("Unknown content being asked for: "
                                  + acceptedContentType);
        }
        profiler.checkpoint("readUserRequest");
        return userRequest;
    }

}
