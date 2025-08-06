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
import java.util.Collection;

public class DomainServletTest extends AbstractAccessControlWebTest<DomainServlet> {


    private final HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
    private final HttpServletResponse mockResponse = createMock(HttpServletResponse.class);


    @Test
    public void doPost() throws IOException {

        final String cookieValue = "Accepted";
        final String targetURL = "http://www.mysite.com/here";
        final String agentServerOne = "www.mysite.mydomain.com";
        final String agentServerTwo = "www.myothersite.mydomain.com";

        final Collection<String> agentServers = new ArrayList<String>();
        agentServers.add(agentServerOne);
        agentServers.add(agentServerTwo);
        setTestSubject(new DomainServlet(agentServers,"/mysite/consent")) ;

        expect(mockRequest.getParameter("cookieValue")).andReturn(cookieValue).once();
        expect(mockRequest.getParameter("targetURL")).andReturn(targetURL).once();

        final String encodedCookieValue =URLEncoder.encode(cookieValue, "UTF-8");
        final String encodedTargetURL = URLEncoder.encode(targetURL, "UTF-8");
        final String encodedSiteOne = URLEncoder.encode(agentServerOne,"UTF-8");
        final String encodedSiteTwo = URLEncoder.encode(agentServerTwo, "UTF-8");

        final String expectedRedirectURL = "/mysite/consent?cookieValue=" + encodedCookieValue + "&referer="
                                            + encodedTargetURL + "&sites=" + encodedSiteOne + ","
                                            + encodedSiteTwo;

        final Writer writer = new StringWriter();
        final PrintWriter printWriter = new PrintWriter(writer);

        mockResponse.setStatus(200);
        expectLastCall().once();

        expect(mockResponse.getWriter()).andReturn(printWriter).once();

        replay(mockRequest, mockResponse);

        getTestSubject().doPost(mockRequest, mockResponse);

        assertEquals("wrong redirect.", expectedRedirectURL, writer.toString());

        verify(mockRequest, mockResponse);

    }

}

