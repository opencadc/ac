/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2016.                            (c) 2016.
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
 *
 ************************************************************************
 */

package ca.nrc.cadc.accesscontrol.web;

import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import ca.nrc.cadc.reg.client.RegistryClient;
import org.apache.log4j.Logger;

import javax.mail.MessagingException;
import javax.security.auth.Subject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URL;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ResourceBundle;

import ca.nrc.cadc.accesscontrol.web.i18n.I18NResourceBundleFactory;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.net.HttpDownload;
import ca.nrc.cadc.net.NetUtil;
import ca.nrc.cadc.util.StringUtil;


public class PasswordResetRequestServlet extends HttpServlet
{
    private static final Logger LOGGER = Logger.getLogger(PasswordResetRequestServlet.class);
    private static final String SERVOPS_PEM = System.getProperty("user.home") + "/.ssl/cadcproxy.pem";


    /**
     * Only acceptable entry.  POST the e-mail address to this endpoint and this
     * will verify the address, and send it a link to reset the password.
     *
     * @param request           The HTTP Request.
     * @param response          The HTTP Response.
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doPost(final HttpServletRequest request,
                          final HttpServletResponse response)
            throws ServletException, IOException
    {
        final Subject servopsSubject =
                SSLUtil.createSubject(new File(SERVOPS_PEM));

        try
        {
            Subject.doAs(servopsSubject, new PrivilegedExceptionAction<Void>()
            {
                @Override
                public Void run() throws Exception
                {
                    PasswordResetRequestServlet.this
                            .processRequest(request, response);
                    return null;
                }
            });
        }
        catch (PrivilegedActionException e)
        {
            final Exception cause = e.getException();

            if (cause == null)
            {
                LOGGER.error("Bug: Unknown error.", e);
            }
            else if (cause instanceof IOException)
            {
                throw ((IOException) cause);
            }
            else if (cause instanceof ServletException)
            {
                throw ((ServletException) cause);
            }
            else
            {
                throw new RuntimeException(cause);
            }
        }
    }

    /**
     * Process a request for this endpoint.  It will pull the parameters down
     * and issue a send mail request.  Building the e-mail entails obtaining a
     * unique token from the AC web service, and sending a unique link via
     * e-mail to the user.
     *
     * @param request               The HTTP Request.
     * @param response              The HTTP Response.
     * @throws IOException
     * @throws MessagingException
     */
    void processRequest(final HttpServletRequest request,
                        final HttpServletResponse response)
            throws IOException, MessagingException
    {
        final String emailAddress = request.getParameter("emailAddress");

        if (StringUtil.hasLength(emailAddress))
        {
            final String lang = request.getParameter("pageLanguage");

            // If the language was not set, we will take care of it here.
            final ResourceBundle i18nBundle = createResourceBundle(lang);

            final Writer writer = new StringWriter();
            final int tokenStatusCode = downloadToken(emailAddress, writer);

            if (tokenStatusCode == 200)
            {
                final String role = request.getParameter("role");

                final SiteRole siteRole = StringUtil.hasLength(role)
                                          ? SiteRole.valueOf(role.toUpperCase())
                                          : SiteRole.CADC;

                final URL requestURL =
                        new URL(request.getRequestURL().toString());
                final WebMailer webMailer = createWebMailer(siteRole,
                                                            requestURL.getHost(),
                                                            i18nBundle);
                final String successRedirect =
                        webMailer.sendMail(emailAddress, writer.toString());

                sendRedirect(response, successRedirect);
            }
            else
            {
                response.sendError(tokenStatusCode);
            }
        }
        else
        {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
        }
    }

    /**
     * Obtain a token for this Request's e-mail address.
     *
     * @param mailAddress The E-mail address to look up.
     * @param writer      The writer to write a token out to.
     * @throws IOException For stream I/O related issues.
     */
    public int downloadToken(final String mailAddress, final Writer writer)
            throws IOException
    {
        final URL serviceURL = getServiceURL();
        final URL resetPasswordURL =
                new URL(serviceURL.toString() + "?emailAddress="
                        + NetUtil.encode(mailAddress));

        final HttpDownload downloader = createDownloader(resetPasswordURL,
                                                         writer);
        downloader.run();

        return downloader.getResponseCode();
    }

    /**
     * Obtain the Access Control service URL.
     *
     * @return The Service URL location.
     * @throws IOException
     */
    URL getServiceURL() throws IOException
    {
        return new RegistryClient().getServiceURL(
                new LocalAuthority().getServiceURI(
                        Standards.UMS_RESETPASS_01.toString()),
                Standards.UMS_RESETPASS_01, AuthMethod.CERT);
    }

    /**
     * Obtain a new instance of an HTTP Download.  Implementors can override.
     *
     * @param writer The writer to write the download to.
     * @return HttpDownload instance.
     * @throws IOException
     */
    HttpDownload createDownloader(final URL serviceURL, final Writer writer)
            throws IOException
    {
        return new HttpDownload(serviceURL,
                                new OutputStream()
                                {
                                    @Override
                                    public void write(final int b)
                                            throws IOException
                                    {
                                        writer.write(b);
                                    }
                                });
    }

    /**
     * Obtain a new WebMailer.  Override for testing.
     *
     * @param siteRole      The SiteRole to use.
     * @param hostName      The hostname.
     * @param i18nBundle    The Resource Bundle language.
     * @return          WebMailer instance.
     */
    WebMailer createWebMailer(final SiteRole siteRole, final String hostName,
                              final ResourceBundle i18nBundle)
    {
        return new WebMailer(siteRole, hostName, i18nBundle);
    }

    ResourceBundle createResourceBundle(final String language)
            throws IOException
    {
        return I18NResourceBundleFactory.getResourceBundle(language);
    }

    private void sendRedirect(final HttpServletResponse response,
                              final String redirectLocation)
            throws IOException
    {
        response.getWriter().write(redirectLocation);
    }
}
