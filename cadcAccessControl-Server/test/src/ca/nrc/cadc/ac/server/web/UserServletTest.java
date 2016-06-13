package ca.nrc.cadc.ac.server.web;


import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;

import java.util.List;

import javax.security.auth.Subject;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;

import junit.framework.Assert;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.easymock.EasyMock;
import org.junit.Test;

import ca.nrc.cadc.db.StandaloneContextFactory;
import ca.nrc.cadc.util.Log4jInit;


public class UserServletTest
{
    private static final Logger log = Logger.getLogger(UserServletTest.class);

    public UserServletTest()
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
    }

    @Test
    public void getAcceptedContentTypeJSON() throws Exception
    {
        final HttpServletRequest mockRequest =
                createMock(HttpServletRequest.class);
        final UserServlet testSubject = new UserServlet();

        expect(mockRequest.getHeader("Accept")).
                andReturn("application/json").once();

        replay(mockRequest);

        assertEquals("Wrong content type.", "application/json",
                     testSubject.getAcceptedContentType(mockRequest));

        verify(mockRequest);
    }

    @Test
    public void getAcceptedContentTypeDefault() throws Exception
    {
        final HttpServletRequest mockRequest =
                createMock(HttpServletRequest.class);
        final UserServlet testSubject = new UserServlet();

        expect(mockRequest.getHeader("Accept")).andReturn(null).once();

        replay(mockRequest);

        assertEquals("Wrong content type.", "text/xml",
                     testSubject.getAcceptedContentType(mockRequest));

        verify(mockRequest);
    }

    @Test
    public void testPrivilegedUsers1()
    {
        try
        {
            StandaloneContextFactory.initJNDI();
            UserServlet userServlet = new UserServlet();
            ServletConfig config = EasyMock.createMock(ServletConfig.class);
            EasyMock.expect(config.getInitParameter(
                UserServlet.class.getName() + ".PrivilegedX500Principals")).
                    andReturn("cn=user1,ou=cadc,o=hia,c=ca cn=user2,ou=cadc,o=hia,c=ca");
            EasyMock.expect(config.getInitParameter(
                UserServlet.class.getName() + ".PrivilegedHttpPrincipals")).
                    andReturn("user1 user2");
            EasyMock.replay(config);
            userServlet.init(config);
            List<Subject> subjects = userServlet.privilegedSubjects;
            Assert.assertTrue(subjects.size() == 2);
            EasyMock.verify(config);
        }
        catch (Exception e)
        {
            log.error("Unexpected", e);
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testPrivilegedUsers2()
    {
        try
        {
            StandaloneContextFactory.initJNDI();
            UserServlet userServlet = new UserServlet();
            ServletConfig config = EasyMock.createMock(ServletConfig.class);
            EasyMock.expect(config.getInitParameter(
                UserServlet.class.getName() + ".PrivilegedX500Principals")).
                    andReturn("\"cn=user1, ou=cadc, o=hia,c=ca\" \"cn=user2, ou=cadc,o=hia,c=ca\"");
            EasyMock.expect(config.getInitParameter(
                UserServlet.class.getName() + ".PrivilegedHttpPrincipals")).
                    andReturn("user1 \"user2\"");
            EasyMock.replay(config);
            userServlet.init(config);
            List<Subject> subjects = userServlet.privilegedSubjects;
            Assert.assertTrue(subjects.size() == 2);
            EasyMock.verify(config);
        }
        catch (Exception e)
        {
            log.error("Unexpected", e);
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testPrivilegedUsers3()
    {
        try
        {
            StandaloneContextFactory.initJNDI();
            UserServlet userServlet = new UserServlet();
            ServletConfig config = EasyMock.createMock(ServletConfig.class);
            EasyMock.expect(config.getInitParameter(
                UserServlet.class.getName() + ".PrivilegedX500Principals")).
                    andReturn("\"cn=user1, ou=cadc, o=hia,c=ca\"");
            EasyMock.expect(config.getInitParameter(
                UserServlet.class.getName() + ".PrivilegedHttpPrincipals")).
                    andReturn("user1");
            EasyMock.replay(config);
            userServlet.init(config);
            List<Subject> subjects = userServlet.privilegedSubjects;
            Assert.assertTrue(subjects.size() == 1);
            EasyMock.verify(config);
        }
        catch (Exception e)
        {
            log.error("Unexpected", e);
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testPrivilegedUsers4()
    {
        try
        {
            StandaloneContextFactory.initJNDI();
            UserServlet userServlet = new UserServlet();
            ServletConfig config = EasyMock.createMock(ServletConfig.class);
            EasyMock.expect(config.getInitParameter(
                UserServlet.class.getName() + ".PrivilegedX500Principals")).
                    andReturn("\"cn=user1, ou=cadc, o=hia,c=ca\" \"cn=user2, ou=cadc,o=hia,c=ca\"");
            EasyMock.expect(config.getInitParameter(
                UserServlet.class.getName() + ".PrivilegedHttpPrincipals")).
                    andReturn("user1 \"user2\" user3");
            EasyMock.replay(config);
            try
            {
                userServlet.init(config);
                Assert.fail("Should have thrown an error");
            }
            catch (ExceptionInInitializerError e)
            {
                // expected
            }
        }
        catch (Exception e)
        {
            log.error("Unexpected", e);
            Assert.fail(e.getMessage());
        }
    }
}
