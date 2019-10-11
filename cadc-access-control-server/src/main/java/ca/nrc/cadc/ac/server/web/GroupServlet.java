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

import java.io.IOException;
import java.security.PrivilegedActionException;

import javax.security.auth.Subject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.server.GroupPersistence;
import ca.nrc.cadc.ac.server.PluginFactory;
import ca.nrc.cadc.ac.server.web.groups.AbstractGroupAction;
import ca.nrc.cadc.ac.server.web.groups.GroupLogInfo;
import ca.nrc.cadc.ac.server.web.groups.GroupsActionFactory;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.NotAuthenticatedException;

/**
 * Servlet for handling all requests to /groups
 *
 * @author majorb
 */
public class GroupServlet extends HttpServlet
{
    private static final long serialVersionUID = 7854660717655869213L;
    private static final Logger log = Logger.getLogger(GroupServlet.class);

    private GroupPersistence groupPersistence;

    @Override
    public void init(ServletConfig config) throws ServletException
    {
        super.init(config);

        try
        {
            PluginFactory pluginFactory = new PluginFactory();
            groupPersistence = pluginFactory.createGroupPersistence();
        }
        catch (Throwable t)
        {
            log.fatal("Error initializing group persistence", t);
            throw new ExceptionInInitializerError(t);
        }
    }

    @Override
    public void destroy()
    {
        groupPersistence.destroy();
    }

    /**
     * Create a GroupAction and run the action safely.
     */
    private void doAction(GroupsActionFactory factory, HttpServletRequest request, HttpServletResponse response)
        throws IOException
    {
        long start = System.currentTimeMillis();
        GroupLogInfo logInfo = new GroupLogInfo(request, this.getClass());
        try
        {
            log.info(logInfo.start());
            Subject subject = AuthenticationUtil.getSubject(request);
            logInfo.setSubject(subject);

            AbstractGroupAction action = factory.createAction(request);

            action.setLogInfo(logInfo);
            action.setHttpServletRequest(request);
            SyncOutput syncOut = new SyncOutput(response);
            action.setSyncOut(syncOut);
            action.setGroupPersistence(groupPersistence);

            try
            {
                if (subject == null)
                {
                    action.run();
                }
                else
                {
                    Subject.doAs(subject, action);
                }
            }
            catch (PrivilegedActionException e)
            {
                Throwable cause = e.getCause();
                if (cause != null)
                {
                    throw cause;
                }
                Exception exception = e.getException();
                if (exception != null)
                {
                    throw exception;
                }
                throw e;
            }
        }
        catch (IllegalArgumentException e)
        {
            log.debug(e.getMessage(), e);
            logInfo.setMessage(e.getMessage());
            response.getWriter().write(e.getMessage());
            response.setStatus(400);
        }
        catch (NotAuthenticatedException e)
        {
            log.debug(e.getMessage(), e);
            logInfo.setMessage(e.getMessage());
            response.getWriter().write(e.getMessage());
            response.setStatus(401);
        }
        catch (Throwable t)
        {
            String message = "Internal Server Error: " + t.getMessage();
            log.error(message, t);
            logInfo.setSuccess(false);
            logInfo.setMessage(message);
            response.getWriter().write(message);
            response.setStatus(500);
        }
        finally
        {
            logInfo.setElapsedTime(System.currentTimeMillis() - start);
            log.info(logInfo.end());
        }
    }

    @Override
    public void doGet(final HttpServletRequest request, HttpServletResponse response)
        throws IOException
    {
        doAction(GroupsActionFactory.httpGetFactory(), request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws IOException
    {
        doAction(GroupsActionFactory.httpPostFactory(), request, response);
    }

    @Override
    public void doDelete(HttpServletRequest request, HttpServletResponse response)
        throws IOException
    {
        doAction(GroupsActionFactory.httpDeleteFactory(), request, response);
    }

    @Override
    public void doPut(HttpServletRequest request, HttpServletResponse response)
        throws IOException
    {
        doAction(GroupsActionFactory.httpPutFactory(), request, response);
    }

    @Override
    public void doHead(HttpServletRequest request, HttpServletResponse response)
        throws IOException
    {
        doAction(GroupsActionFactory.httpHeadFactory(), request, response);
    }

}
