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
import java.net.URI;
import java.security.AccessControlException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Set;
import java.util.TimeZone;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserAlreadyExistsException;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.server.ACScopeValidator;
import ca.nrc.cadc.ac.server.PluginFactory;
import ca.nrc.cadc.ac.server.UserPersistence;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.DelegationToken;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.ServletPrincipalExtractor;
import ca.nrc.cadc.log.ServletLogInfo;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.util.StringUtil;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Servlet to handle password resets.  Passwords are an integral part of the
 * access control system and are handled differently to accommodate stricter
 * guidelines.
 * <p>
 * This servlet handles GET and POST only.  It relies on the Subject being set higher
 * up by the AccessControlFilter as configured in the web descriptor.
 */
public class ResetPasswordServlet extends HttpServlet
{
    private static final Logger log = Logger.getLogger(ResetPasswordServlet.class);

    List<Subject> privilegedSubjects;
    UserPersistence userPersistence;

    /**
     * Servlet initialization method.
     * 
     * <p>
     * Receives the servlet configuration object and initializes UserPersistence 
     * using input parameters read from it. Users who do augment
     * subject calls are constructed by taking the principals out of the ServletConfig 
     * input parameter.
     * 
     * <p>
     * The ResetPasswordServlet configuration in the web deployment descriptor file 
     * <code>web.xml</code> must have two input parameters:
     * <ul>
     * <li><code>ca.nrc.cadc.ac.server.web.ResetPasswordServlet.PrivilegedX500Principals</code>
     * is a list of trusted administrators DNs. It is a multi-line list with
     * line breaks between the trusted DNs and each DN eclosed in double quotes.
     * <li><code>ca.nrc.cadc.ac.server.web.ResetPasswordServlet.PrivilegedHttpPrincipals</code>
     * is a list of space separated userids (HTTP identities) corresponding 
     * to the previous DNs.
     * </ul>
     * The two lists of principal names must be of the same
     * length and correspond to each other in order.
     * 
     * @param config           The servlet configuration object.
     * @param response         The HTTP Response.
     * 
     * @throws javax.servlet.ServletException   For general Servlet exceptions.
     */
    @Override
    public void init(final ServletConfig config) throws ServletException
    {
        super.init(config);

        try
        {
            String x500Users = config.getInitParameter(ResetPasswordServlet.class.getName() + ".PrivilegedX500Principals");
            log.debug("privilegedX500Users: " + x500Users);

            String httpUsers = config.getInitParameter(ResetPasswordServlet.class.getName() + ".PrivilegedHttpPrincipals");
            log.debug("privilegedHttpUsers: " + httpUsers);

            List<String> x500List = new ArrayList<String>();
            List<String> httpList = new ArrayList<String>();
            if (x500Users != null && httpUsers != null)
            {
                Pattern pattern = Pattern.compile("([^\"]\\S*|\".+?\")\\s*");
                Matcher x500Matcher = pattern.matcher(x500Users);
                Matcher httpMatcher = pattern.matcher(httpUsers);

                while (x500Matcher.find())
                {
                    String next = x500Matcher.group(1);
                    x500List.add(next.replace("\"", ""));
                }

                while (httpMatcher.find())
                {
                    String next = httpMatcher.group(1);
                    httpList.add(next.replace("\"", ""));
                }

                if (x500List.size() != httpList.size())
                {
                    throw new RuntimeException("Init exception: Lists of augment subject principals not equivalent in length");
                }

                privilegedSubjects = new ArrayList<Subject>(x500Users.length());
                for (int i=0; i<x500List.size(); i++)
                {
                    Subject s = new Subject();
                    s.getPrincipals().add(new X500Principal(x500List.get(i)));
                    s.getPrincipals().add(new HttpPrincipal(httpList.get(i)));
                    privilegedSubjects.add(s);
                }

            }
            else
            {
                log.warn("No Privileged users configured.");
            }

            PluginFactory pluginFactory = new PluginFactory();
            userPersistence = pluginFactory.createUserPersistence();
        }
        catch (Throwable t)
        {
            log.fatal("Error initializing group persistence", t);
            throw new ExceptionInInitializerError(t);
        }
    }

    protected boolean isPrivilegedSubject(final HttpServletRequest request)
    {
        if (privilegedSubjects == null || privilegedSubjects.isEmpty())
        {
            return false;
        }

        ServletPrincipalExtractor extractor = new ServletPrincipalExtractor(request);
        Set<Principal> principals = extractor.getPrincipals();

        for (Principal principal : principals)
        {
            if (principal instanceof X500Principal)
            {
                for (Subject s : privilegedSubjects)
                {
                    Set<X500Principal> x500Principals = s.getPrincipals(X500Principal.class);
                    for (X500Principal p2 : x500Principals)
                    {
                        if (p2.getName().equalsIgnoreCase(principal.getName()))
                        {
                            return true;
                        }
                    }
                }
            }

            if (principal instanceof HttpPrincipal)
            {
                for (Subject s : privilegedSubjects)
                {
                    Set<HttpPrincipal> httpPrincipals = s.getPrincipals(HttpPrincipal.class);
                    for (HttpPrincipal p2 : httpPrincipals)
                    {
                        if (p2.getName().equalsIgnoreCase(principal.getName()))
                        {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    /**
     * Handle a /ac GET operation. The subject provided is expected to be a privileged user.
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
            logInfo.setSubject(subject);
            if ((subject == null) || (subject.getPrincipals().isEmpty()))
            {
                logInfo.setMessage("Unauthorized subject");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
            else
            {
                if (isPrivilegedSubject(request))
                {
                    String token = (String) Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
                    {
                        public Object run() throws Exception
                        {
                            String emailAddress = request.getParameter("emailAddress");
                            if (StringUtil.hasText(emailAddress))
                            {
                                User user = userPersistence.getUserByEmailAddress(emailAddress);
                                HttpPrincipal userID = (HttpPrincipal) user.getHttpPrincipal();
                                URI scopeURI = new URI(ACScopeValidator.RESET_PASSWORD_SCOPE);
                                int duration = 24; // hours
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
                else
                {
                    logInfo.setMessage("Permission denied subject");
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                }
            }
        }
        catch (Throwable t)
        {
            try
            {
                if (t instanceof PrivilegedActionException)
                {
                    Exception e = ((PrivilegedActionException) t).getException();
                    if (e != null)
                    {
                        throw e;
                    }
                }

                throw t;
            }
            catch (UserAlreadyExistsException e)
            {
                log.debug(e.getMessage(), e);
                logInfo.setMessage(e.getMessage());
                response.setStatus(HttpServletResponse.SC_CONFLICT);
            }
            catch (UserNotFoundException e)
            {
                log.debug(e.getMessage(), e);
                logInfo.setMessage(e.getMessage());
                response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            }
            catch (IllegalArgumentException e)
            {
                log.debug(e.getMessage(), e);
                logInfo.setMessage(e.getMessage());
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            }
            catch (TransientException e)
            {
                log.debug(e.getMessage(), e);
                String message = e.getMessage();
                logInfo.setMessage(message);
                logInfo.setSuccess(false);
                response.setContentType("text/plain");
                if (e.getRetryDelay() > 0)
                    response.setHeader("Retry-After", Integer.toString(e.getRetryDelay()));
                response.getWriter().write("Transient Error: " + message);
                response.setStatus(503);
            }
            catch (AccessControlException e)
            {
                log.debug(e.getMessage(), e);
                logInfo.setMessage(e.getMessage());
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
            catch (Throwable t1)
            {
                String message = "Internal Server Error: " + t.getMessage();
                log.error(message, t);
                logInfo.setSuccess(false);
                logInfo.setMessage(message);
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }
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
     */
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
                        {
                            throw new IllegalStateException("no HttpPrincipal in subject");
                        }

                        HttpPrincipal userID = pset.iterator().next();

                        String newPassword = request.getParameter("password");
                        if (StringUtil.hasText(newPassword))
                        {
                            userPersistence.resetPassword(userID, newPassword);
                        }
                        else
                        {
                            throw new IllegalArgumentException("Missing password");
                        }

                        return null;
                    }
                });
            }
        }
        catch (Throwable t)
        {
            try
            {
                if (t instanceof PrivilegedActionException)
                {
                    Exception e = ((PrivilegedActionException) t).getException();
                    if (e != null)
                    {
                        throw e;
                    }
                }

                throw t;
            }
            catch (UserNotFoundException e)
            {
                log.debug(e.getMessage(), e);
                logInfo.setMessage(e.getMessage());
                response.setStatus(HttpServletResponse.SC_NOT_FOUND);
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
            catch (Throwable t1)
            {
                String message = "Internal Server Error: " + t.getMessage();
                log.error(message, t);
                logInfo.setSuccess(false);
                logInfo.setMessage(message);
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }
        }
        finally
        {
            logInfo.setElapsedTime(System.currentTimeMillis() - start);
            log.info(logInfo.end());
        }
     }

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
