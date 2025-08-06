/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2019.                         (c) 2019.
 * Government of Canada                 Gouvernement du Canada
 * National Research Council            Conseil national de recherches
 * Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 * All rights reserved                  Tous droits reserves
 *
 * NRC disclaims any warranties         Le CNRC denie toute garantie
 * expressed, implied, or statu-        enoncee, implicite ou legale,
 * tory, of any kind with respect       de quelque nature que se soit,
 * to the software, including           concernant le logiciel, y com-
 * without limitation any war-          pris sans restriction toute
 * ranty of merchantability or          garantie de valeur marchande
 * fitness for a particular pur-        ou de pertinence pour un usage
 * pose.  NRC shall not be liable       particulier.  Le CNRC ne
 * in any event for any damages,        pourra en aucun cas etre tenu
 * whether direct or indirect,          responsable de tout dommage,
 * special or general, consequen-       direct ou indirect, particul-
 * tial or incidental, arising          ier ou general, accessoire ou
 * from the use of the software.        fortuit, resultant de l'utili-
 *                                      sation du logiciel.
 *
 *
 * @author dhawann
 * 08/01/19 - 10:07 AM
 *
 *
 *
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */


package ca.nrc.cadc.accesscontrol.web;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.SSOCookieManager;
import org.easymock.EasyMock;
import org.junit.Test;

import ca.nrc.cadc.accesscontrol.AbstractAccessControlWebTest;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.TimeZone;

public class ConsentCookieServletTest extends AbstractAccessControlWebTest<ConsentCookieServlet>   {

    private final HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
    private final HttpServletResponse mockResponse = createMock(HttpServletResponse.class);


    public void assignCookies(Cookie[] cookiesArray) {
        cookiesArray[0] = new Cookie("__utma","80067852");
        cookiesArray[1] = new Cookie("__utmb","80067852.22891766.");
        cookiesArray[2] = new Cookie("__utmz","1559592689");
    }



    @Test
    public void doGet1() throws IOException {
        setTestSubject(new ConsentCookieServlet());

        final Writer writer = new StringWriter();
        final PrintWriter printWriter = new PrintWriter(writer);

        expect(mockResponse.getWriter()).andReturn(printWriter).once();

        Cookie[] cookies = null;

        Cookie[] cookiesArray = new Cookie[4];

        assignCookies(cookiesArray);
        cookiesArray[3] = new Cookie("__utmt","1");
        expect(mockRequest.getCookies()).andReturn(cookiesArray);


        replay(mockResponse, mockRequest);

        getTestSubject().doGet(mockRequest, mockResponse);

        verify(mockResponse, mockRequest);

        assertCheckCookieExists("does not exist", writer.toString() );
    }

    @Test
    public void doGet2() throws IOException {

        setTestSubject(new ConsentCookieServlet());

        final Writer writer = new StringWriter();
        final PrintWriter printWriter = new PrintWriter(writer);

        expect(mockResponse.getWriter()).andReturn(printWriter).once();

        Cookie[] cookies = null;

        Cookie[] cookiesArray = new Cookie[4];

        assignCookies(cookiesArray);
        cookiesArray[3] = new Cookie("Consent-Cookie","Accepted");
        expect(mockRequest.getCookies()).andReturn(cookiesArray);

        replay(mockResponse, mockRequest);

        getTestSubject().doGet(mockRequest, mockResponse);

        verify(mockResponse, mockRequest);

        assertCheckCookieExists("exists", writer.toString() );

    }

    private void assertCheckCookieExists(final String expectedValue, final String cookieValue)  {
        assertEquals(expectedValue, cookieValue);
    }

}

