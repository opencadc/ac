/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2012.                         (c) 2012.
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
 * @author jenkinsd
 * 4/20/12 - 2:43 PM
 *
 *
 *
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */

package ca.nrc.cadc.accesscontrol.web;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.SSOCookieManager;
import ca.nrc.cadc.date.DateUtil;
import org.junit.Test;

import ca.nrc.cadc.accesscontrol.AbstractAccessControlWebTest;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;

public class SSOCookieAgentImplTest extends AbstractAccessControlWebTest<SSOCookieAgentImpl> {
    private final HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
    private final HttpServletResponse mockResponse = createMock(HttpServletResponse.class);

    @Test
    public void issueCookie() throws Exception {
        final SSOCookieManager cookieManager = new SSOCookieManager() {
            /**
             * Testers can override this to provide a consistent test.
             *
             * @return Calendar instance.  Never null.
             */
            @Override
            public Calendar getCurrentCalendar() {
                final Calendar expiryCal = Calendar.getInstance(DateUtil.UTC);

                // Dustin's 60th birthday.
                expiryCal.set(2037, Calendar.NOVEMBER, 25, 3, 21, 0);
                expiryCal.set(Calendar.MILLISECOND, 0);

                return expiryCal;
            }
        };

        final Collection<String> agents = Collections.singletonList("host.com");

        setTestSubject(new SSOCookieAgentImpl(cookieManager, agents, "sso://cadc.com/go") {
            @Override
            int getCookieLifetimeSeconds() {
                return 88;
            }
        });

        Set<Principal> principalSet = new HashSet<>();
        principalSet.add(new HttpPrincipal("CADCtest"));
        final String cookieValue = cookieManager.generate(principalSet, null);

        expect(mockResponse.getHeaderNames()).andReturn(Collections.emptyList()).once();

        mockResponse.setHeader("set-cookie",
                               String.format("CADC_SSO=\"%s\"; Secure; SameSite=None; HttpOnly; Domain=%s; Max-Age=88; Path=/",
                                             cookieValue, "cadc.dao.nrc.ca"));
        expectLastCall().once();

        expect(mockRequest.getRequestURI()).andReturn("/access/do/endpoint").once();
        expect(mockRequest.getServerName()).andReturn("mach.cadc.dao.nrc.ca").once();

        replay(mockResponse, mockRequest);

        getTestSubject().issueCookie(cookieValue, mockRequest, mockResponse);

        verify(mockResponse, mockRequest);
    }

    @Test
    public void validateToken() throws Exception {
        final SSOCookieManager cookieManager = new SSOCookieManager() {
            /**
             * Testers can override this to provide a consistent test.
             *
             * @return Calendar instance.  Never null.
             */
            @Override
            public Calendar getCurrentCalendar() {
                final Calendar expiryCal = Calendar.getInstance(DateUtil.UTC);

                // Dustin's 60th birthday.
                expiryCal.set(2037, Calendar.NOVEMBER, 25, 3, 21, 0);
                expiryCal.set(Calendar.MILLISECOND, 0);

                return expiryCal;
            }
        };

        final Collection<String> agentServers = new ArrayList<>();
        agentServers.add("www.mysite.com");
        final String cookieValue =
                cookieManager.generate(Collections.singleton(new HttpPrincipal("CADCtest")), null);

        setTestSubject(new SSOCookieAgentImpl(cookieManager, agentServers, "/mysite/sso"));

        assertValidateToken(true, cookieValue);
        assertValidateToken(false, "ASDF-20394-ASDA");
        // This shall not pass after cadc-util v 1.5.3
//        assertValidateToken(false, null);
        assertValidateToken(false, "  ");
    }

    @Test
    public void doPost() throws Exception {
        final SSOCookieManager cookieManager = new SSOCookieManager() {
            /**
             * Testers can override this to provide a consistent test.
             *
             * @return Calendar instance.  Never null.
             */
            @Override
            public Calendar getCurrentCalendar() {
                final Calendar expiryCal = Calendar.getInstance(DateUtil.UTC);

                // Dustin's 60th birthday.
                expiryCal.set(2037, Calendar.NOVEMBER, 25, 3, 21, 0);
                expiryCal.set(Calendar.MILLISECOND, 0);

                return expiryCal;
            }
        };

        // null here is set to use the default scope of sso:cadc+canfar
        Set<Principal> principalSet = new HashSet<>();
        principalSet.add(new HttpPrincipal("CADCtest"));
        final String cookieValue = cookieManager.generate(principalSet, null);

        final String targetURL = "http://www.mysite.com/here";
        final String agentServerOne = "www.mysite.mydomain.com";
        final String agentServerTwo = "www.myothersite.mydomain.com";

        final Collection<String> agentServers = new ArrayList<>();
        agentServers.add(agentServerOne);
        agentServers.add(agentServerTwo);

        setTestSubject(new SSOCookieAgentImpl(cookieManager, agentServers,"/mysite/sso"));

        expect(mockRequest.getParameter("targetURL")).andReturn(targetURL).once();
        expect(mockRequest.getParameter("cookieValue")).andReturn(cookieValue).once();

        final String encodedCookieValue = URLEncoder.encode(cookieValue, StandardCharsets.UTF_8.name());
        final String encodedTargetURL = URLEncoder.encode(targetURL, StandardCharsets.UTF_8.name());
        final String encodedSiteOne = URLEncoder.encode(agentServerOne, StandardCharsets.UTF_8.name());
        final String encodedSiteTwo = URLEncoder.encode(agentServerTwo, StandardCharsets.UTF_8.name());
        final String expectedRedirectURL = "/mysite/sso?cookieValue=" + encodedCookieValue + "&referer="
                                           + encodedTargetURL + "&sites=" + encodedSiteOne + ","
                                           + encodedSiteTwo;

        final Writer writer = new StringWriter();
        final PrintWriter printWriter = new PrintWriter(writer);

        mockResponse.setStatus(200);
        expectLastCall().once();

        expect(mockResponse.getWriter()).andReturn(printWriter).once();

        replay(mockRequest, mockResponse);

        getTestSubject().doPost(mockRequest, mockResponse);

        assertEquals("Wrong redirect.", expectedRedirectURL, writer.toString());

        verify(mockRequest, mockResponse);
    }

    private void assertValidateToken(final boolean shouldPass, final String cookieValue) throws Exception {
        if (shouldPass) {
            assertTrue("Should be fine.",
                getTestSubject().validateToken(cookieValue));
        } else {
            assertFalse("Should not be fine.",
                getTestSubject().validateToken(cookieValue));
        }
    }
}
