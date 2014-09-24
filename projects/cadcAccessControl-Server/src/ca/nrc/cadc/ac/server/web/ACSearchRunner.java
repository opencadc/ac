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

import java.security.AccessControlException;
import java.security.Principal;
import java.util.Collection;
import java.util.Date;

import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.GroupsWriter;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.server.GroupPersistence;
import ca.nrc.cadc.ac.server.PluginFactory;
import ca.nrc.cadc.ac.server.RequestValidator;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.uws.ExecutionPhase;
import ca.nrc.cadc.uws.Job;
import ca.nrc.cadc.uws.server.JobRunner;
import ca.nrc.cadc.uws.server.JobUpdater;
import ca.nrc.cadc.uws.server.SyncOutput;
import ca.nrc.cadc.uws.util.JobLogInfo;

public class ACSearchRunner
    implements JobRunner
{
    private static Logger log = Logger.getLogger(ACSearchRunner.class);
    
    private JobUpdater jobUpdater;
    private SyncOutput syncOut;
    private Job job;
    private JobLogInfo logInfo;

    @Override
    public void setJobUpdater(JobUpdater jobUpdater)
    {
        this.jobUpdater = jobUpdater;
    }

    @Override
    public void setJob(Job job)
    {
        this.job = job;
    }

    @Override
    public void setSyncOutput(SyncOutput syncOut)
    {
        this.syncOut = syncOut;
    }

    @Override
    public void run()
    {
        log.debug("RUN ACSearchRunner: " + job.ownerSubject);
        
        logInfo = new JobLogInfo(job);

        String startMessage = logInfo.start();
        log.info(startMessage);

        long t1 = System.currentTimeMillis();
        search();
        long t2 = System.currentTimeMillis();

        logInfo.setElapsedTime(t2 - t1);

        String endMessage = logInfo.end();
        log.info(endMessage);
    }
    
    private void search()
    {
        
        // Note: This search runner is customized to run with
        // InMemoryJobPersistence, and synchronous POST requests are
        // dealt with immediately, rather than returning results via
        // a redirect.
        // Jobs in this runner are never updated after execution begins
        // in case the in-memory job has gone away.  Error reporting
        // is done directly through the response on both POST and GET
        
        try
        {
            ExecutionPhase ep = 
                jobUpdater.setPhase(job.getID(), ExecutionPhase.QUEUED, 
                                    ExecutionPhase.EXECUTING, new Date());
            if ( !ExecutionPhase.EXECUTING.equals(ep) )
            {
                throw new IllegalStateException("QUEUED -> EXECUTING [FAILED]");
            }
            log.debug(job.getID() + ": QUEUED -> EXECUTING [OK]");

            RequestValidator rv = new RequestValidator();
            rv.validate(job.getParameterList());
            
            Principal userID = 
                AuthenticationUtil.createPrincipal(rv.getUserID(), 
                                                   rv.getIDType().getValue());
            
            PluginFactory factory = new PluginFactory();
            GroupPersistence dao = factory.getGroupPersistence();
            Collection<Group> groups = 
                dao.getGroups(userID, rv.getRole(), rv.getGroupID());
            syncOut.setResponseCode(HttpServletResponse.SC_OK);
            GroupsWriter.write(groups, syncOut.getOutputStream());
            
            // Mark the Job as completed.
//            jobUpdater.setPhase(job.getID(), ExecutionPhase.EXECUTING, 
//                                ExecutionPhase.COMPLETED, new Date());
        }
        catch (TransientException t)
        {
            logInfo.setSuccess(false);
            logInfo.setMessage(t.getMessage());
            log.error("FAIL", t);
            
            syncOut.setResponseCode(503);
            
//            ErrorSummary errorSummary =
//                new ErrorSummary(t.getMessage(), ErrorType.FATAL);
//            try
//            {
//                jobUpdater.setPhase(job.getID(), ExecutionPhase.EXECUTING,
//                                    ExecutionPhase.ERROR, errorSummary, 
//                                    new Date());
//            }
//            catch(Throwable oops)
//            {
//                log.debug("failed to set final error status after " + t, oops);
//            }
        }
        catch (UserNotFoundException t)
        {
            logInfo.setSuccess(false);
            logInfo.setMessage(t.getMessage());
            log.debug("FAIL", t);
            
            syncOut.setResponseCode(404);
            
//            ErrorSummary errorSummary =
//                new ErrorSummary(t.getMessage(), ErrorType.FATAL);
//            try
//            {
//                jobUpdater.setPhase(job.getID(), ExecutionPhase.EXECUTING,
//                                    ExecutionPhase.ERROR, errorSummary,
//                                    new Date());
//            }
//            catch(Throwable oops)
//            {
//                log.debug("failed to set final error status after " + t, oops);
//            }
        }
        catch (GroupNotFoundException t)
        {
            logInfo.setSuccess(false);
            logInfo.setMessage(t.getMessage());
            log.debug("FAIL", t);
            
            syncOut.setResponseCode(404);
            
//            ErrorSummary errorSummary =
//                new ErrorSummary(t.getMessage(), ErrorType.FATAL);
//            try
//            {
//                jobUpdater.setPhase(job.getID(), ExecutionPhase.EXECUTING,
//                                    ExecutionPhase.ERROR, errorSummary,
//                                    new Date());
//            }
//            catch(Throwable oops)
//            {
//                log.debug("failed to set final error status after " + t, oops);
//            }
        }
        catch (AccessControlException t)
        {
            logInfo.setSuccess(false);
            logInfo.setMessage(t.getMessage());
            log.debug("FAIL", t);
            
            syncOut.setResponseCode(401);
            
//            ErrorSummary errorSummary =
//                new ErrorSummary(t.getMessage(), ErrorType.FATAL);
//            try
//            {
//                jobUpdater.setPhase(job.getID(), ExecutionPhase.EXECUTING,
//                                    ExecutionPhase.ERROR, errorSummary,
//                                    new Date());
//            }
//            catch(Throwable oops)
//            {
//                log.debug("failed to set final error status after " + t, oops);
//            }
        }
        catch (Throwable t)
        {
            logInfo.setSuccess(false);
            logInfo.setMessage(t.getMessage());
            log.error("FAIL", t);
            
            syncOut.setResponseCode(500);
            
//            ErrorSummary errorSummary =
//                new ErrorSummary(t.getMessage(), ErrorType.FATAL);
//            try
//            {
//                jobUpdater.setPhase(job.getID(), ExecutionPhase.EXECUTING,
//                                    ExecutionPhase.ERROR, errorSummary,
//                                    new Date());
//            }
//            catch(Throwable oops)
//            {
//                log.debug("failed to set final error status after " + t, oops);
//            }
        }
    }
    
//    private Principal getUserPrincipal(String userID, IdentityType type)
//    {
//        if (type == IdentityType.OPENID)
//        {
//            return new OpenIdPrincipal(userID);
//        }
//        if (type == IdentityType.UID)
//        {
//            try
//            {
//                Long numericId = Long.valueOf(userID);
//                return new NumericPrincipal(numericId);
//            }
//            catch (NumberFormatException e)
//            {
//                throw new IllegalArgumentException("Illegal UID userID " +
//                                                   userID + " because " +
//                                                   e.getMessage());
//            }
//        }
//        if (type == IdentityType.USERNAME)
//        {
//            return new HttpPrincipal(userID);
//        }
//        if (type == IdentityType.X500)
//        {
//            return new X500Principal(userID);
//        }
//        throw new IllegalArgumentException("Unknown user type " + 
//                                           type.getValue());
//    }
    
}
