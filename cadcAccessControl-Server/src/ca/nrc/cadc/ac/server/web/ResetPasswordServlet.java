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

import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.server.ACScopeValidator;
import ca.nrc.cadc.ac.server.PluginFactory;
import ca.nrc.cadc.ac.server.UserPersistence;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.DelegationToken;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.log.ServletLogInfo;
import ca.nrc.cadc.util.StringUtil;

import org.apache.log4j.Logger;

import javax.security.auth.Subject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.net.URI;
import java.security.AccessControlException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Set;
import java.util.TimeZone;

/**
 * Servlet to handle password resets.  Passwords are an integral part of the
 * access control system and are handled differently to accommodate stricter
 * guidelines.
 * <p/>
 * This servlet handles GET and POST only.  It relies on the Subject being set higher
 * up by the AccessControlFilter as configured in the web descriptor.
 */
public class ResetPasswordServlet extends HttpServlet
{
    private static final Logger log = Logger.getLogger(ResetPasswordServlet.class);

    UserPersistence<Principal> userPersistence;

    @Override
    public void init(final ServletConfig config) throws ServletException
    {
        super.init(config);

        PluginFactory pluginFactory = new PluginFactory();
        userPersistence = pluginFactory.createUserPersistence();
    }
    /**
     * Handle a /ac GET operation. The subject provided is expected to be servops.
     *
     * @param request  The HTTP Request.
     * @param response The HTTP Response.
     * @throws ServletException Anything goes wrong at the Servlet level.
     * @throws IOException      Any reading/writing errors.
     */
    @Override
    protected void doGet(final HttpServletRequest request,
                         final HttpServletResponse response)
            throws ServletException, IOException
    {
        final long start = System.currentTimeMillis();
        final ServletLogInfo logInfo = new ServletLogInfo(request);
        log.info(logInfo.start());
        try
        {
            final Subject subject = getSubject(request);
            final Set<HttpPrincipal> currentWebPrincipals =
                    subject.getPrincipals(HttpPrincipal.class);

            if (currentWebPrincipals.isEmpty())
            {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
            else
            {
                String token = (String) Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
                {
                    public Object run() throws Exception
                    {
                        String email = request.getParameter("emailAddress");
                        if (StringUtil.hasText(email))
                        {
                            User<Principal> user = userPersistence.getUserByEmailAddress(email);
                            HttpPrincipal userID = (HttpPrincipal) user.getUserID();
                            URI scopeURI = new URI(ACScopeValidator.SCOPE);
                            int duration = 2; // hours
                            Calendar expiry = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
                            expiry.add(Calendar.HOUR, duration);
                            DelegationToken dt = new DelegationToken(userID, scopeURI, expiry.getTime());

                            return DelegationToken.format(dt);
                        }
                        else
                        {
                            throw new IllegalArgumentException("Missing email address");
                        }
                    }
                });
                
                response.setContentType("text/plain");
                response.setContentLength(token.length());
                response.getWriter().write(token);
            }
        }
        catch (PrivilegedActionException pae)
        {
            Exception e = pae.getException();
            if (e != null)
            {
                String msg = e.getMessage();
                log.debug(msg, e);
                logInfo.setMessage(msg);
                if (msg.contains("User not found "))
                {            
                    response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                }
                else
                {
                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                }
            }
        }
        catch (IllegalArgumentException e)
        {
            log.debug(e.getMessage(), e);
            logInfo.setMessage(e.getMessage());
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        }
        catch (Throwable t)
        {
            String message = "Internal Server Error: " + t.getMessage();
            log.error(message, t);
            logInfo.setSuccess(false);
            logInfo.setMessage(message);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
        finally
        {
            logInfo.setElapsedTime(System.currentTimeMillis() - start);
            log.info(logInfo.end());
        }
    }

    /**
     * Attempt to change password.
     *
     * @param request  The HTTP Request.
     * @param response The HTTP Response.
     * @throws IOException Any errors that are not expected.
     *
    public void doPost(final HttpServletRequest request,
                       final HttpServletResponse response)
            throws IOException
    {
        final long start = System.currentTimeMillis();
        final ServletLogInfo logInfo = new ServletLogInfo(request);
        log.info(logInfo.start());
        try
        {
            final Subject subject = getSubject(request);
            logInfo.setSubject(subject);
            if ((subject == null) || (subject.getPrincipals().isEmpty()))
            {
                logInfo.setMessage("Unauthorized subject");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
            else
            {
                Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
                {
                    public Object run() throws Exception
                    {
                        
                        Set<HttpPrincipal> pset = subject.getPrincipals(HttpPrincipal.class);
                        if (pset.isEmpty())
                            throw new IllegalStateException("no HttpPrincipal in subject");
                        HttpPrincipal userID = pset.iterator().next();

                        String oldPassword = request.getParameter("old_password");
                        String newPassword = request.getParameter("new_password");
                        if (StringUtil.hasText(oldPassword))
                        {
                            if (StringUtil.hasText(newPassword))
                            {
                                userPersistence.setPassword(userID, oldPassword, newPassword);
                            }
                            else
                            {
                                throw new IllegalArgumentException("Missing new password");
                            }
                        }
                        else
                        {
                            throw new IllegalArgumentException("Missing old password");
                        }
                        return null;
                    }
                });
            }
        }
        catch (IllegalArgumentException e)
        {
            log.debug(e.getMessage(), e);
            logInfo.setMessage(e.getMessage());
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        }
        catch (AccessControlException e)
        {
            log.debug(e.getMessage(), e);
            logInfo.setMessage(e.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
        catch (Throwable t)
        {
            String message = "Internal Server Error: " + t.getMessage();
            log.error(message, t);
            logInfo.setSuccess(false);
            logInfo.setMessage(message);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
        finally
        {
            logInfo.setElapsedTime(System.currentTimeMillis() - start);
            log.info(logInfo.end());
        }
    }
    */

    /**
     * Get and augment the Subject. Tests can override this method.
     *
     * @param request Servlet request
     * @return augmented Subject
     */
    Subject getSubject(final HttpServletRequest request)
    {
        return AuthenticationUtil.getSubject(request);
    }
}
