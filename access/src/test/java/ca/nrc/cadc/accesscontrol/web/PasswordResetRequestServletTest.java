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

import ca.nrc.cadc.accesscontrol.AbstractAccessControlWebTest;

import ca.nrc.cadc.net.HttpDownload;
import ca.nrc.cadc.net.NetUtil;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URL;
import java.util.*;

import static org.junit.Assert.*;
import static org.easymock.EasyMock.*;


public class PasswordResetRequestServletTest
        extends AbstractAccessControlWebTest<PasswordResetRequestServlet>
{
    @Test
    public void downloadToken() throws Exception
    {
        final HttpDownload mockHTTPDownload = createMock(HttpDownload.class);

        setTestSubject(new PasswordResetRequestServlet()
        {
            /**
             * Obtain the Access Control service URL.
             *
             * @return The Service URL location.
             * @throws IOException
             */
            @Override
            URL getServiceURL() throws IOException
            {
//                return new URL("http://mysecuresite.com/get/?emailAddress="
//                               + NetUtil.encode(mailAddress));
                return new URL("http://mysecuresite.com/get");
            }

            /**
             * Obtain a new instance of an HTTP Download.  Implementors can override.
             *
             * @param serviceURL The service URL.
             * @param writer     The writer to write the download to.
             * @return HttpDownload instance.
             * @throws IOException
             */
            @Override
            HttpDownload createDownloader(URL serviceURL, Writer writer)
                    throws IOException
            {
                writer.write("TOKEN44");
                return mockHTTPDownload;
            }
        });

        final Writer writer = new StringWriter();

        mockHTTPDownload.run();
        expectLastCall().once();

        expect(mockHTTPDownload.getResponseCode()).andReturn(200).once();

        replay(mockHTTPDownload);

        getTestSubject().downloadToken("me@domain.com", writer);

        assertEquals("Wrong token.", "TOKEN44", writer.toString());

        verify(mockHTTPDownload);
    }

    @Test
    public void processRequest() throws Exception
    {
        final HttpServletRequest mockRequest =
                createMock(HttpServletRequest.class);
        final HttpServletResponse mockResponse =
                createMock(HttpServletResponse.class);
        final WebMailer mockWebMailer = createMock(WebMailer.class);
        final HttpDownload mockHTTPDownload = createMock(HttpDownload.class);
        final Writer writer = new StringWriter();
        final PrintWriter printWriter = new PrintWriter(writer);
        final Map<String, String> bundleMap = new HashMap<>();

        bundleMap.put("ORG_ACRONYM_CADC", "CADC");
        bundleMap.put("ORG_NAME_CADC", "Astonomy centre for Canada");
        bundleMap.put("BODY_CONTENT",
                      "MESSAGE %s WITH %s TOKEN REPLACEMENTS %s.");
        bundleMap.put("ORG_FROM_EMAIL_ADDRESS_CADC", "cadc@cadc.ca");
        bundleMap.put("ORG_NEW_PASSWORD_PAGE_CADC",
                      "/fr/auth/nouveauMotDePasse.html");
        bundleMap.put("EMAIL_SUBJECT", "Mon sujet");
        bundleMap.put("ORG_LOGIN_PAGE_CADC", "/eng/login.html");

        final ResourceBundle stubBundle = new ResourceBundle()
        {
            @Override
            protected Object handleGetObject(final String key)
            {
                return bundleMap.get(key);
            }

            @Override
            public Enumeration<String> getKeys()
            {
                return Collections.emptyEnumeration();
            }
        };


        setTestSubject(new PasswordResetRequestServlet()
        {
            /**
             * Obtain the Access Control service URL.
             *
             * @return The Service URL location.
             * @throws IOException
             */
            @Override
            URL getServiceURL() throws IOException
            {
//                return new URL("http://mysecuresite.com/get/?emailAddress="
//                               + NetUtil.encode(mailAddress));
                return new URL("http://mysecuresite.com/get");
            }

            /**
             * Obtain a new instance of an HTTP Download.  Implementors can override.
             *
             * @param serviceURL The Service URL.
             * @param writer     The writer to write the download to.
             * @return HttpDownload instance.
             * @throws IOException
             */
            @Override
            HttpDownload createDownloader(URL serviceURL, Writer writer)
                    throws IOException
            {
                writer.write("TOKEN77");
                return mockHTTPDownload;
            }

            @Override
            ResourceBundle createResourceBundle(final String language)
            {
                return stubBundle;
            }

            /**
             * Obtain a new WebMailer.  Override for testing.
             *
             * @param siteRole   The SiteRole to use.
             * @param hostName   The hostname.
             * @param i18nBundle The Resource Bundle language.
             * @return WebMailer instance.
             */
            @Override
            WebMailer createWebMailer(SiteRole siteRole, String hostName,
                                      ResourceBundle i18nBundle)
            {
                return mockWebMailer;
            }
        });

        expect(mockRequest.getParameter("emailAddress")).andReturn(
                "myemail@cadc.ca").once();
        expect(mockRequest.getParameter("role")).andReturn("cadc").once();
        expect(mockRequest.getParameter("pageLanguage")).andReturn("en").once();
        expect(mockRequest.getRequestURL()).andReturn(
                new StringBuffer("http://astrosite.ca/do/something")).once();

        expect(mockResponse.getWriter()).andReturn(printWriter).once();

        expect(mockWebMailer.sendMail("myemail@cadc.ca", "TOKEN77")).andReturn(
                "http://astrosite.ca/en/login.html").once();

        mockHTTPDownload.run();
        expectLastCall().once();

        expect(mockHTTPDownload.getResponseCode()).andReturn(200).once();

        replay(mockRequest, mockResponse, mockWebMailer, mockHTTPDownload);

        getTestSubject().processRequest(mockRequest, mockResponse);

        assertEquals("Payload output is wrong.",
                     "http://astrosite.ca/en/login.html", writer.toString());

        verify(mockRequest, mockResponse, mockWebMailer, mockHTTPDownload);
    }
}
