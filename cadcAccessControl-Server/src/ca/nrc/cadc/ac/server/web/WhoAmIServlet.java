/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2015.                            (c) 2015.
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

package ca.nrc.cadc.ac.server.web;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.util.Set;

import javax.security.auth.Subject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.reg.Standards;
import org.apache.log4j.Logger;

import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.log.ServletLogInfo;
import ca.nrc.cadc.reg.client.LocalAuthority;
import ca.nrc.cadc.reg.client.RegistryClient;

/**
 * Servlet to handle GET requests asking for the current User.  This servlet
 * will implement the /whoami functionality to return details about the
 * currently authenticated user, or rather, the user whose Subject is currently
 * found in this context.
 */
public class WhoAmIServlet extends HttpServlet
{
    private static final Logger log = Logger.getLogger(WhoAmIServlet.class);

    static final String USER_GET_PATH = "/%s?idType=HTTP";

    /**
     * Handle a /whoami GET operation.
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
            final Subject currentSubject = getSubject(request);
            final Set<HttpPrincipal> currentWebPrincipals =
                    currentSubject.getPrincipals(HttpPrincipal.class);

            if (currentWebPrincipals.isEmpty())
            {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
            else
            {
                redirect(response, currentWebPrincipals.toArray(
                        new HttpPrincipal[1])[0], request.getScheme());
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
     * Forward on to the Service's user endpoint.
     *
     * @param response     The HTTP response.
     * @param webPrincipal The HttpPrincipal instance.
     * @param scheme       The scheme
     */
    void redirect(final HttpServletResponse response,
                  final HttpPrincipal webPrincipal,
                  final String scheme) throws IOException
    {
        final RegistryClient registryClient = getRegistryClient();

        LocalAuthority localAuthority = new LocalAuthority();
        URI umsServiceURI = localAuthority.getServiceURI("ums");
        log.debug("ums service uri: " + umsServiceURI);

        final URL serviceURL = registryClient.getServiceURL(umsServiceURI, Standards.UMS_USERS_01, AuthMethod.CERT);
        final URL redirectURL = new URL(serviceURL.toExternalForm() + USER_GET_PATH);

        // Take the first one.
        final String redirectUrl =
            String.format(redirectURL.toString(), webPrincipal.getName());
        final URI redirectURI = URI.create(redirectUrl);

        log.debug("redirecting to " + redirectURI.toASCIIString());

        response.sendRedirect(redirectURI.getPath() + "?" + redirectURI.getQuery());
    }

    /**
     * Tests will need to override this method so as not to rely on the
     * environment.
     *
     * @return      Registry Client instance.
     */
    RegistryClient getRegistryClient()
    {
        return new RegistryClient();
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
