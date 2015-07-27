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
package ca.nrc.cadc.ac.server.web.groups;

import java.io.IOException;
import java.security.AccessControlException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.List;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.GroupAlreadyExistsException;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.MemberAlreadyExistsException;
import ca.nrc.cadc.ac.MemberNotFoundException;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.server.GroupPersistence;
import ca.nrc.cadc.ac.server.PluginFactory;
import ca.nrc.cadc.ac.server.UserPersistence;
import ca.nrc.cadc.net.TransientException;

public abstract class GroupsAction
    implements PrivilegedExceptionAction<Object>
{
    private static final Logger log = Logger.getLogger(GroupsAction.class);
    protected GroupLogInfo logInfo;
    protected HttpServletResponse response;

    GroupsAction(GroupLogInfo logInfo)
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
        catch (MemberNotFoundException e)
        {
            log.debug(e.getMessage(), e);
            String message = "Member not found: " + e.getMessage();
            this.logInfo.setMessage(message);
            sendError(404, message);
        }
        catch (GroupNotFoundException e)
        {
            log.debug(e.getMessage(), e);
            String message = "Group not found: " + e.getMessage();
            this.logInfo.setMessage(message);
            sendError(404, message);
        }
        catch (UserNotFoundException e)
        {
            log.debug(e.getMessage(), e);
            String message = "User not found: " + e.getMessage();
            this.logInfo.setMessage(message);
            sendError(404, message);
        }
        catch (MemberAlreadyExistsException e)
        {
            log.debug(e.getMessage(), e);
            String message = "Member already exists: " + e.getMessage();
            this.logInfo.setMessage(message);
            sendError(409, message);
        }
        catch (GroupAlreadyExistsException e)
        {
            log.debug(e.getMessage(), e);
            String message = "Group already exists: " + e.getMessage();
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

    <T extends Principal> GroupPersistence<T> getGroupPersistence()
    {
        PluginFactory pluginFactory = new PluginFactory();
        return pluginFactory.getGroupPersistence();
    }

    <T extends Principal> UserPersistence<T> getUserPersistence()
    {
        PluginFactory pluginFactory = new PluginFactory();
        return pluginFactory.getUserPersistence();
    }

    protected void logGroupInfo(String groupID, List<String> deletedMembers, List<String> addedMembers)
    {
        this.logInfo.groupID = groupID;
        this.logInfo.addedMembers = addedMembers;
        this.logInfo.deletedMembers = deletedMembers;
    }

}
