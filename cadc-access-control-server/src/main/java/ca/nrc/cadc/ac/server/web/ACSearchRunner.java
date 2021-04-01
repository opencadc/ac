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

package ca.nrc.cadc.ac.server.web;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.server.GroupPersistence;
import ca.nrc.cadc.ac.server.PluginFactory;
import ca.nrc.cadc.ac.xml.GroupListWriter;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.rest.SyncOutput;
import ca.nrc.cadc.uws.ExecutionPhase;
import ca.nrc.cadc.uws.Job;
import ca.nrc.cadc.uws.Parameter;
import ca.nrc.cadc.uws.ParameterUtil;
import ca.nrc.cadc.uws.server.JobRunner;
import ca.nrc.cadc.uws.server.JobUpdater;
import ca.nrc.cadc.uws.util.JobLogInfo;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.AccessControlContext;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.Principal;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.security.auth.Subject;

import org.apache.log4j.Logger;

public class ACSearchRunner implements JobRunner {
    private static Logger log = Logger.getLogger(ACSearchRunner.class);

    private JobUpdater jobUpdater;
    private SyncOutput syncOut;
    private Job job;
    private JobLogInfo logInfo;

    private Set<String> groupNames = new HashSet<String>();
    private Role role;
    private boolean ivoaStandardResponse = false;

    @Override
    public void setJobUpdater(JobUpdater jobUpdater) {
        this.jobUpdater = jobUpdater;
    }

    @Override
    public void setJob(Job job) {
        this.job = job;
    }

    @Override
    public void setSyncOutput(SyncOutput syncOut) {
        this.syncOut = syncOut;
    }

    @Override
    public void run() {
        AccessControlContext acContext = AccessController.getContext();
        Subject subject = Subject.getSubject(acContext);

        log.debug("RUN ACSearchRunner: " + subject);
        if (log.isDebugEnabled()) {
            Set<Principal> principals = subject.getPrincipals();
            Iterator<Principal> i = principals.iterator();
            while (i.hasNext()) {
                Principal next = i.next();
                log.debug("Principal " + next.getClass().getSimpleName() + ": " + next.getName());
            }
        }

        logInfo = new JobLogInfo(job);
        logInfo.setSubject(subject);

        String startMessage = logInfo.start();
        log.info(startMessage);

        long t1 = System.currentTimeMillis();
        search(subject);
        long t2 = System.currentTimeMillis();

        logInfo.setElapsedTime(t2 - t1);

        String endMessage = logInfo.end();
        log.info(endMessage);
    }

    @SuppressWarnings("unchecked")
    private void search(Subject subject) {

        // Note: This search runner is customized to run with
        // InMemoryJobPersistence, and synchronous POST requests are
        // dealt with immediately, rather than returning results via
        // a redirect.
        // Jobs in this runner are never updated after execution begins
        // in case the in-memory job has gone away. Error reporting
        // is done directly through the response on both POST and GET

        try {
            ExecutionPhase ep = jobUpdater.setPhase(job.getID(), ExecutionPhase.QUEUED, ExecutionPhase.EXECUTING,
                    new Date());
            if (!ExecutionPhase.EXECUTING.equals(ep)) {
                throw new IllegalStateException("QUEUED -> EXECUTING [FAILED]");
            }
            log.debug(job.getID() + ": QUEUED -> EXECUTING [OK]");

            validateParams(job.getParameterList());

            PluginFactory factory = new PluginFactory();
            GroupPersistence dao = factory.createGroupPersistence();
            Collection<Group> groups = new HashSet<Group>();
            if (groupNames.isEmpty()) {
                groups.addAll(dao.getGroups(role, null));
            } else {
                for (String groupName : groupNames) {
                    try {
                        groups.addAll(dao.getGroups(role, groupName));
                    } catch (GroupNotFoundException ignore) {
                        log.debug("no memberships found");
                    }
                }
            }
            
            // TODO: change response type based on RESPONSEFORMAT param or Accept header
            if (ivoaStandardResponse) {
                if (groups.size() > 0) {
                    StringBuilder response = new StringBuilder();
                    for (Group g : groups) {
                        response.append(g.getID().getName());
                        response.append("\n");
                    }
                    syncOut.setHeader("Content-Type", "text/plain");
                    syncOut.getOutputStream().write(response.toString().getBytes());
                }
            } else {
                GroupListWriter groupListWriter = new GroupListWriter();
                groupListWriter.write(groups, syncOut.getOutputStream());
            }
            
        } catch (TransientException t) {
            logInfo.setSuccess(false);
            logInfo.setMessage(t.getMessage());
            log.error("FAIL", t);

            syncOut.setCode(503);
            syncOut.setHeader("Content-Type", "text/plain");
            if (t.getRetryDelay() > 0)
                syncOut.setHeader("Retry-After", Integer.toString(t.getRetryDelay()));
            try {
                syncOut.getOutputStream().write(("Transient Exception: " + t.getMessage()).getBytes());
            } catch (IOException e) {
                log.warn("Could not write response to output stream", e);
            }
        } catch (UserNotFoundException t) {
            logInfo.setSuccess(true);
            logInfo.setMessage(t.getMessage());
            log.debug("FAIL", t);

            syncOut.setCode(404);
            syncOut.setHeader("Content-Type", "text/plain");
            try {
                syncOut.getOutputStream().write(t.getMessage().getBytes());
            } catch (IOException e) {
                log.warn("Could not write response to output stream", e);
            }
        } catch (IllegalArgumentException ex) {
            logInfo.setSuccess(true);
            logInfo.setMessage(ex.getMessage());
            log.debug("FAIL", ex);

            syncOut.setCode(400);
            syncOut.setHeader("Content-Type", "text/plain");
            try {
                syncOut.getOutputStream().write(ex.getMessage().getBytes());
            } catch (IOException e) {
                log.warn("Could not write response to output stream", e);
            }
        } catch (AccessControlException t) {
            logInfo.setSuccess(true);
            logInfo.setMessage(t.getMessage());
            log.debug("FAIL", t);

            syncOut.setCode(403);
            syncOut.setHeader("Content-Type", "text/plain");
            try {
                syncOut.getOutputStream().write("Permission Denied".getBytes());
            } catch (IOException e) {
                log.warn("Could not write response to output stream", e);
            }
        } catch (Throwable t) {
            logInfo.setSuccess(false);
            logInfo.setMessage(t.getMessage());
            log.error("FAIL", t);

            writeError(syncOut, 500, t);
        }
    }

    private void writeError(SyncOutput syncOutput, int code, Throwable t) {
        try {
            syncOutput.setCode(code);
            syncOut.setHeader("Content-Type", "text/plain");
            OutputStream ostream = syncOut.getOutputStream();
            if (ostream != null) {
                OutputStreamWriter w = new OutputStreamWriter(ostream);
                w.write(t.toString());
                w.flush();
            }
        } catch (IOException e) {
            log.warn("Could not write response to output stream", e);
        }
    }

    /**
     * Validate the incoming parameters.
     * 
     * IVOA GMS requests can be:
     *   - (no params) - list group memberships
     *   - one or more group=[groupName] params - is member of {groupName1} - {groupNameN}?
     * CADC parameter extensions of GMS standard:
     *   - role=[role] - list groups in role (member, admin, or owner)
     *   - role=[role] groupID=[groupName}] - list group if user has specified role in group
     * 
     * @param params The incoming parameters.
     */
    void validateParams(List<Parameter> params) {
        
        if (params == null) {
            throw new IllegalArgumentException("missing parameters");
        }
        
        String roleParam = ParameterUtil.findParameterValue("ROLE", params);
        // GROUPID param support is deprecated
        String groupIDParam = ParameterUtil.findParameterValue("GROUPID", params);
        // ivoa param name is 'group'
        List<String> groupParams = ParameterUtil.findParameterValues("group", params);
        
        // ivoa search for all memberships is request with no params
        if (roleParam == null && groupIDParam == null && groupParams.isEmpty()) {
            // default to membership role
            this.role = Role.MEMBER;
            ivoaStandardResponse = true;
            return;
        }
        
        if (!groupParams.isEmpty()) {
            // set will drop duplicates
            this.groupNames.addAll(groupParams);
            if (roleParam != null) {
                // allow role with vo param, but use xml response
                this.role = Role.toValue(roleParam);
            } else {
                ivoaStandardResponse = true;
                role = Role.MEMBER;
            }
            return;
        }
        
        // role is required
        if (roleParam != null) {
            this.role = Role.toValue(roleParam);
        } else {
            throw new IllegalArgumentException("required parameter ROLE not found");
        }
        
        // groupID is optional
        if (groupIDParam != null) {
            this.groupNames.add(groupIDParam);
        }

    }
    
    Role getRole() {
        return role;
    }
    
    Set<String> getGroupNames() {
        return groupNames;
    }
    
    boolean isIvoaStandardResponse() {
        return ivoaStandardResponse;
    }

}
