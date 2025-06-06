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

import ca.nrc.cadc.ac.GroupAlreadyExistsException;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.MemberAlreadyExistsException;
import ca.nrc.cadc.ac.MemberNotFoundException;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.server.GroupPersistence;
import ca.nrc.cadc.ac.server.web.SyncOutput;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.reg.client.LocalAuthority;
import java.io.IOException;
import java.net.URI;
import java.security.AccessControlException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Iterator;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;
import org.apache.log4j.Logger;

public abstract class AbstractGroupAction implements PrivilegedExceptionAction<Object> {
    private static final Logger log = Logger.getLogger(AbstractGroupAction.class);

    protected boolean isPrivilegedUser = false;
    protected GroupLogInfo logInfo;
    protected HttpServletRequest request;
    protected SyncOutput syncOut;
    protected GroupPersistence groupPersistence;

    public AbstractGroupAction() {
    }

    abstract void doAction() throws Exception;

    public void setIsPrivilegedUser(boolean isPrivilegedUser) {
        this.isPrivilegedUser = isPrivilegedUser;
    }

    public boolean isPrivilegedUser() {
        return this.isPrivilegedUser;
    }

    public void setLogInfo(GroupLogInfo logInfo) {
        this.logInfo = logInfo;
    }

    public void setHttpServletRequest(HttpServletRequest request) {
        this.request = request;
    }

    public void setSyncOut(SyncOutput syncOut) {
        this.syncOut = syncOut;
    }

    public void setGroupPersistence(GroupPersistence groupPersistence) {
        this.groupPersistence = groupPersistence;
    }

    public URI getServiceURI(URI standard) {
        LocalAuthority localAuthority = new LocalAuthority();
        return localAuthority.getServiceURI(standard.toString());
    }

    public Object run() throws PrivilegedActionException {
        try {
            doAction();
        } catch (AccessControlException e) {
            log.debug(e.getMessage(), e);
            String message = "Permission Denied: " + e.getMessage();
            this.logInfo.setMessage(message);
            sendError(403, message);
        } catch (IllegalArgumentException e) {
            log.debug(e.getMessage(), e);
            String message = "Bad request: " + e.getMessage();
            this.logInfo.setMessage(message);
            sendError(400, message);
        } catch (MemberNotFoundException e) {
            log.debug(e.getMessage(), e);
            String message = "Member not found: " + e.getMessage();
            this.logInfo.setMessage(message);
            sendError(404, message);
        } catch (GroupNotFoundException e) {
            log.debug(e.getMessage(), e);
            String message = "Group not found: " + e.getMessage();
            this.logInfo.setMessage(message);
            sendError(404, message);
        } catch (UserNotFoundException e) {
            log.debug(e.getMessage(), e);
            String message = "User not found: " + e.getMessage();
            this.logInfo.setMessage(message);
            sendError(404, message);
        } catch (MemberAlreadyExistsException e) {
            log.debug(e.getMessage(), e);
            String message = "Member already exists: " + e.getMessage();
            this.logInfo.setMessage(message);
            sendError(409, message);
        } catch (GroupAlreadyExistsException e) {
            log.debug(e.getMessage(), e);
            String message = "Group already exists: " + e.getMessage();
            this.logInfo.setMessage(message);
            sendError(409, message);
        } catch (UnsupportedOperationException e) {
            log.debug(e.getMessage(), e);
            this.logInfo.setMessage("Not yet implemented.");
            sendError(501);
        } catch (TransientException e) {
            String message = "Transient Error: " + e.getMessage();
            this.logInfo.setSuccess(false);
            this.logInfo.setMessage(message);
            if (e.getRetryDelay() > 0)
                syncOut.setHeader("Retry-After", Integer.toString(e.getRetryDelay()));
            log.error(message, e);
            sendError(503, message);
        } catch (Throwable t) {
            log.error("Internal Error", t);
            String message = "Internal Error: " + t.getMessage();
            this.logInfo.setSuccess(false);
            sendError(500, message);
            this.logInfo.setMessage(message);
        }
        return null;
    }

    private void sendError(int responseCode) {
        sendError(responseCode, null);
    }

    private void sendError(int responseCode, String message) {
        syncOut.setHeader("Content-Type", "text/plain");
        syncOut.setCode(responseCode);
        if (message != null) {
            try {
                syncOut.getWriter().write(message);
            } catch (IOException e) {
                log.warn("Could not write error message to output stream");
            }
        }
    }

    protected void logGroupInfo(String groupID, List<String> deletedMembers, List<String> addedMembers) {
        this.logInfo.groupID = groupID;
        this.logInfo.addedMembers = addedMembers;
        this.logInfo.deletedMembers = deletedMembers;
    }

    protected String getUseridForLogging(User u) {
        if (u.getIdentities().isEmpty())
            return "anonUser";

        Iterator<Principal> i = u.getIdentities().iterator();
        String ret = null;
        Principal next = null;
        while (i.hasNext()) {
            next = i.next();
            if (next instanceof HttpPrincipal)
                return next.getName();
            if (next instanceof X500Principal)
                ret = next.getName();
            else if (ret == null)
                ret = next.getName();
        }
        return ret;
    }


}
