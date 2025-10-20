
/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2019.                            (c) 2019.
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

package org.opencadc.proxy;

import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.net.FileContent;
import ca.nrc.cadc.net.HttpPost;
import ca.nrc.cadc.net.HttpTransfer;
import ca.nrc.cadc.net.HttpUpload;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.util.StringUtil;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Servlet to proxy requests from pages serving JavaScript.  This proxying mechanism exists to work around security
 * systems preventing JavaScript requests directly to web services that reside on a different domain.
 * This servlet supports GET, POST, and PUT requests for now.
 * Any proxying will ALWAYS follow redirects.
 */
public class ProxyServlet extends HttpServlet {

    private static final String REQUEST_HEADER_PREFIX = "X-CADC-Proxy_";

    /**
     * Useful for overriding in tests.
     *
     * @return RegistryClient instance.  Never null.
     */
    RegistryClient getRegistryClient() {
        return new RegistryClient();
    }

    private Map<String, String[]> buildRequestParameterMap(final Map<String, String[]> requestParameters) {
        final Map<String, String[]> requestParameterMap = new HashMap<>();
        for (final RequestParameterName requestParameterName : RequestParameterName.values()) {
            final String[] values = requestParameters.get(requestParameterName.name());
            if (values != null) {
                requestParameterMap.put(requestParameterName.name(), values);
            }
        }

        return requestParameterMap;
    }

    private ServiceParameterMap buildServiceParameterMap(final Map<String, String[]> requestParameters) {
        final ServiceParameterMap serviceParameterMap = new ServiceParameterMap();
        for (final ServiceParameterName serviceParameterName : ServiceParameterName.values()) {
            serviceParameterMap.putFirst(serviceParameterName, requestParameters.get(serviceParameterName.name()));
        }

        return serviceParameterMap;
    }

    private ServiceParameterMap buildServiceParameterMap(final HttpServletRequest request) {
        final ServiceParameterMap serviceParameterMap = new ServiceParameterMap();
        for (final ServiceParameterName serviceParameterName : ServiceParameterName.values()) {
            serviceParameterMap.put(serviceParameterName,
                                    request.getHeader(REQUEST_HEADER_PREFIX + serviceParameterName.name()));
        }

        return serviceParameterMap;
    }

    URL lookupServiceURL(final ServiceParameterMap serviceParameters) throws IOException {
        final RegistryClient registryClient = getRegistryClient();

        final URL serviceURL =
                registryClient.getServiceURL(serviceParameters.getURI(ServiceParameterName.RESOURCE_ID),
                                             serviceParameters.getURI(ServiceParameterName.STANDARD_ID),
                                             AuthMethod.valueOf(serviceParameters.get(ServiceParameterName.AUTH_TYPE)
                                                                                 .toUpperCase()),
                                             serviceParameters.getURI(ServiceParameterName.INTERFACE_TYPE_ID));

        if (serviceURL == null) {
            throw new IllegalArgumentException("No Service URL matching provided parameters:\n\n"
                                               + serviceParameters + "\n\n");
        } else {

            final URL serviceURLWithPath;
            if (serviceParameters.containsKey(ServiceParameterName.EXTRA_PATH)) {
                final String extraPath = serviceParameters.get(ServiceParameterName.EXTRA_PATH);
                serviceURLWithPath = new URL(serviceURL, serviceURL.getPath() + "/" + extraPath);
            } else {
                serviceURLWithPath = serviceURL;
            }

            final URL serviceURLWithQuery;
            if (serviceParameters.containsKey(ServiceParameterName.EXTRA_QUERY)) {
                final String extraQuery = serviceParameters.get(ServiceParameterName.EXTRA_QUERY);
                serviceURLWithQuery = new URL(serviceURLWithPath,
                                              serviceURLWithPath.getPath() + (extraQuery.startsWith("?") ? extraQuery
                                                                                                         : "?"
                                                                                                           + extraQuery));
            } else {
                serviceURLWithQuery = serviceURLWithPath;
            }

            return serviceURLWithQuery;
        }
    }

    URL lookupServiceURL(final Map<String, String[]> parameters) throws IOException {
        final ServiceParameterMap serviceParameters = buildServiceParameterMap(parameters);
        return lookupServiceURL(serviceParameters);
    }

    URL lookupServiceURL(final HttpServletRequest request) throws IOException {
        final ServiceParameterMap serviceParameters = buildServiceParameterMap(request);
        return lookupServiceURL(serviceParameters);
    }

    HttpPost getHttpPost(final URL url, final Map<String, String[]> payload) {
        final Map<String, Object> postPayload = new HashMap<>();
        for (final Map.Entry<String, String[]> entry : payload.entrySet()) {
            postPayload.put(entry.getKey(), Arrays.asList(entry.getValue()));
        }
        return new HttpPost(url, postPayload, false);
    }

    HttpPost getHttpPost(final URL url, final byte[] data, final String contentType) {
        return new HttpPost(url, new FileContent(data, contentType), false);
    }

    /**
     * Called by the server (via the <code>service</code> method)
     * to allow a servlet to handle a POST request.
     * The HTTP POST method allows the client to send
     * data of unlimited length to the Web server a single time
     * and is useful when posting information such as
     * credit card numbers.
     *
     * <p>When overriding this method, read the request data,
     * write the response headers, get the response's writer or output
     * stream object, and finally, write the response data. It's best
     * to include content type and encoding. When using a
     * <code>PrintWriter</code> object to return the response, set the
     * content type before accessing the <code>PrintWriter</code> object.
     *
     * <p>The servlet container must write the headers before committing the
     * response, because in HTTP the headers must be sent before the
     * response body.
     *
     * <p>Where possible, set the Content-Length header (with the
     * {@link ServletResponse#setContentLength} method),
     * to allow the servlet container to use a persistent connection
     * to return its response to the client, improving performance.
     * The content length is automatically set if the entire response fits
     * inside the response buffer.
     *
     * <p>When using HTTP 1.1 chunked encoding (which means that the response
     * has a Transfer-Encoding header), do not set the Content-Length header.
     *
     * <p>This method does not need to be either safe or idempotent.
     * Operations requested through POST can have side effects for
     * which the user can be held accountable, for example,
     * updating stored data or buying items online.
     *
     * <p>If the HTTP POST request is incorrectly formatted,
     * <code>doPost</code> returns an HTTP "Bad Request" message.
     *
     * @param req  an {@link HttpServletRequest} object that
     *             contains the request the client has made
     *             of the servlet
     * @param resp an {@link HttpServletResponse} object that
     *             contains the response the servlet sends
     *             to the client
     * @throws IOException If the desired redirect is not possible.
     * @see ServletOutputStream
     * @see ServletResponse#setContentType
     */
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        final URL serviceURL = lookupServiceURL(req.getParameterMap());
        final Map<String, String[]> parameterMap = buildRequestParameterMap(req.getParameterMap());
        final HttpPost post;

        if (parameterMap.containsKey(RequestParameterName.DATA.name())) {
            final byte[] data = parameterMap.get(RequestParameterName.DATA.name())[0].getBytes();
            final String contentType;
            if (parameterMap.containsKey(RequestParameterName.DATA_CONTENT_TYPE.name())) {
                contentType = parameterMap.get(RequestParameterName.DATA_CONTENT_TYPE.name())[0];
            } else {
                contentType = "application/json";
            }

            post = getHttpPost(serviceURL, data, contentType);
        } else {
            post = getHttpPost(serviceURL, req.getParameterMap());
        }

        post.setRequestProperty("Accept", req.getHeader("Accept"));
        post.run();

        final URL redirectURL = post.getRedirectURL();

        if (redirectURL == null) {
            resp.setContentType(post.getContentType());
            resp.setStatus(post.getResponseCode());
        } else {
            final HttpProxy proxyRedirect = getHttpProxy(redirectURL, resp);
            proxyRedirect.run();
        }
    }

    HttpUpload getHttpUpload(final URL url, final InputStream inputStream) {
        return new HttpUpload(inputStream, url);
    }

    /**
     * Called by the server (via the <code>service</code> method)
     * to allow a servlet to handle a PUT request.
     * The PUT operation allows a client to
     * place a file on the server and is similar to
     * sending a file by FTP.
     *
     * <p>When overriding this method, leave intact
     * any content headers sent with the request (including
     * Content-Length, Content-Type, Content-Transfer-Encoding,
     * Content-Encoding, Content-Base, Content-Language, Content-Location,
     * Content-MD5, and Content-Range). If your method cannot
     * handle a content header, it must issue an error message
     * (HTTP 501 - Not Implemented) and discard the request.
     * For more information on HTTP 1.1, see RFC 2616
     * <a href="http://www.ietf.org/rfc/rfc2616.txt"></a>.
     *
     * <p>This method does not need to be either safe or idempotent.
     * Operations that <code>doPut</code> performs can have side
     * effects for which the user can be held accountable. When using
     * this method, it may be useful to save a copy of the
     * affected URL in temporary storage.
     *
     * <p>If the HTTP PUT request is incorrectly formatted,
     * <code>doPut</code> returns an HTTP "Bad Request" message.
     *
     * @param req  the {@link HttpServletRequest} object that
     *             contains the request the client made of
     *             the servlet
     * @param resp the {@link HttpServletResponse} object that
     *             contains the response the servlet returns
     *             to the client
     * @throws IOException if an input or output error occurs
     *                     while the servlet is handling the
     *                     PUT request
     */
    @Override
    protected void doPut(final HttpServletRequest req, final HttpServletResponse resp) throws IOException {
        final URL serviceURL = lookupServiceURL(req);
        final HttpUpload put = getHttpUpload(serviceURL, req.getInputStream());

        put.setRequestProperty("Accept", req.getHeader("Accept"));
        put.setRequestProperty(HttpTransfer.CONTENT_TYPE, req.getContentType());
        put.run();

        resp.setStatus(put.getResponseCode());
    }

    HttpProxy getHttpProxy(final URL url, final HttpServletResponse response) {
        return new HttpProxy(url, response);
    }

    /**
     * Called by the server (via the <code>service</code> method) to
     * allow a servlet to handle a GET request.
     *
     * <p>Overriding this method to support a GET request also
     * automatically supports an HTTP HEAD request. A HEAD
     * request is a GET request that returns no body in the
     * response, only the request header fields.
     *
     * <p>When overriding this method, read the request data,
     * write the response headers, get the response's writer or
     * output stream object, and finally, write the response data.
     * It's best to include content type and encoding. When using
     * a <code>PrintWriter</code> object to return the response,
     * set the content type before accessing the
     * <code>PrintWriter</code> object.
     *
     * <p>The servlet container must write the headers before
     * committing the response, because in HTTP the headers must be sent
     * before the response body.
     *
     * <p>Where possible, set the Content-Length header (with the
     * {@link ServletResponse#setContentLength} method),
     * to allow the servlet container to use a persistent connection
     * to return its response to the client, improving performance.
     * The content length is automatically set if the entire response fits
     * inside the response buffer.
     *
     * <p>When using HTTP 1.1 chunked encoding (which means that the response
     * has a Transfer-Encoding header), do not set the Content-Length header.
     *
     * <p>The GET method should be safe, that is, without
     * any side effects for which users are held responsible.
     * For example, most form queries have no side effects.
     * If a client request is intended to change stored data,
     * the request should use some other HTTP method.
     *
     * <p>The GET method should also be idempotent, meaning
     * that it can be safely repeated. Sometimes making a
     * method safe also makes it idempotent. For example,
     * repeating queries is both safe and idempotent, but
     * buying a product online or modifying data is neither
     * safe nor idempotent.
     *
     * <p>If the request is incorrectly formatted, <code>doGet</code>
     * returns an HTTP "Bad Request" message.
     *
     * @param req  an {@link HttpServletRequest} object that
     *             contains the request the client has made
     *             of the servlet
     * @param resp an {@link HttpServletResponse} object that
     *             contains the response the servlet sends
     *             to the client
     * @throws IOException if an input or output error is
     *                     detected when the servlet handles
     *                     the GET request
     * @see ServletResponse#setContentType
     */
    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws IOException {
        final URL serviceURL = lookupServiceURL(req.getParameterMap());
        final HttpProxy proxy = getHttpProxy(serviceURL, resp);

        final String contentType = req.getContentType();

        if (StringUtil.hasText(contentType)) {
            proxy.setRequestProperty("Content-Type", contentType);
        }

        final String acceptContentType = req.getHeader("Accept");

        if (StringUtil.hasText(acceptContentType)) {
            proxy.setRequestProperty("Accept", acceptContentType);
        }

        proxy.run();
    }
}
