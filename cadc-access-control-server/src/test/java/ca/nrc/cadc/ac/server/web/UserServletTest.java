package ca.nrc.cadc.ac.server.web;


import ca.nrc.cadc.ac.server.PluginFactory;
import ca.nrc.cadc.db.StandaloneContextFactory;
import ca.nrc.cadc.util.Log4jInit;
import ca.nrc.cadc.util.PropertiesReader;
import java.util.List;
import javax.security.auth.Subject;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.easymock.EasyMock;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import junit.framework.Assert;
import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;


public class UserServletTest {
    private static final Logger log = Logger.getLogger(UserServletTest.class);

    public UserServletTest() {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
    }

    @BeforeClass
    public static void setupClass() {
        System.setProperty(PropertiesReader.class.getName() + ".dir", "src/test/resources");
    }

    @AfterClass
    public static void teardownClass() {
        System.clearProperty(PropertiesReader.class.getName() + ".dir");
    }

    @Test
    public void getAcceptedContentTypeJSON() throws Exception {
        final HttpServletRequest mockRequest =
                createNiceMock(HttpServletRequest.class);
        final UserServlet testSubject = new UserServlet();

        expect(mockRequest.getHeader("Accept")).
                andReturn("application/json").once();

        replay(mockRequest);

        assertEquals("Wrong content type.", "application/json",
                testSubject.getAcceptedContentType(mockRequest));

        verify(mockRequest);
    }

    @Test
    public void getAcceptedContentTypeDefault() throws Exception {
        final HttpServletRequest mockRequest =
                createNiceMock(HttpServletRequest.class);
        final UserServlet testSubject = new UserServlet();

        expect(mockRequest.getHeader("Accept")).andReturn(null).once();

        replay(mockRequest);

        assertEquals("Wrong content type.", "text/xml",
                testSubject.getAcceptedContentType(mockRequest));

        verify(mockRequest);
    }

    @Test
    public void testPrivilegedUsers1() {
        try {
            final PluginFactory piMock = EasyMock.createNiceMock(PluginFactory.class);
            EasyMock.expect(piMock.createUserPersistence()).andReturn(null).once();
            StandaloneContextFactory.initJNDI();
            UserServlet userServlet = new UserServlet() {
                @Override
                public PluginFactory getPluginFactory() {
                    return piMock;
                }
            };

            StandaloneContextFactory.initJNDI();
            ServletConfig config = EasyMock.createNiceMock(ServletConfig.class);
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
        } catch (Exception e) {
            log.error("Unexpected", e);
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testPrivilegedUsers2() {
        try {
            final PluginFactory piMock = EasyMock.createNiceMock(PluginFactory.class);
            EasyMock.expect(piMock.createUserPersistence()).andReturn(null).once();
            StandaloneContextFactory.initJNDI();
            UserServlet userServlet = new UserServlet() {
                @Override
                public PluginFactory getPluginFactory() {
                    return piMock;
                }
            };

            StandaloneContextFactory.initJNDI();
            ServletConfig config = EasyMock.createNiceMock(ServletConfig.class);
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
        } catch (Exception e) {
            log.error("Unexpected", e);
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testPrivilegedUsers3() {
        try {
            final PluginFactory piMock = EasyMock.createNiceMock(PluginFactory.class);
            EasyMock.expect(piMock.createUserPersistence()).andReturn(null).once();
            StandaloneContextFactory.initJNDI();
            UserServlet userServlet = new UserServlet() {
                @Override
                public PluginFactory getPluginFactory() {
                    return piMock;
                }
            };
            ServletConfig config = EasyMock.createNiceMock(ServletConfig.class);
            EasyMock.expect(config.getInitParameter(
                            UserServlet.class.getName() + ".PrivilegedX500Principals")).
                    andReturn("\"cn=user1, ou=cadc, o=hia,c=ca\"");
            EasyMock.expect(config.getInitParameter(
                            UserServlet.class.getName() + ".PrivilegedHttpPrincipals")).
                    andReturn("user1");
            EasyMock.replay(config, piMock);
            userServlet.init(config);
            List<Subject> subjects = userServlet.privilegedSubjects;
            Assert.assertTrue(subjects.size() == 1);
            EasyMock.verify(config);
        } catch (Exception e) {
            log.error("Unexpected", e);
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testPrivilegedUsers4() {
        try {
            StandaloneContextFactory.initJNDI();
            final PluginFactory piMock = EasyMock.createNiceMock(PluginFactory.class);
            EasyMock.expect(piMock.createUserPersistence()).andReturn(null).once();
            StandaloneContextFactory.initJNDI();
            UserServlet userServlet = new UserServlet() {
                @Override
                public PluginFactory getPluginFactory() {
                    return piMock;
                }
            };
            ServletConfig config = EasyMock.createNiceMock(ServletConfig.class);
            EasyMock.expect(config.getInitParameter(
                            UserServlet.class.getName() + ".PrivilegedX500Principals")).
                    andReturn("\"cn=user1, ou=cadc, o=hia,c=ca\" \"cn=user2, ou=cadc,o=hia,c=ca\"");
            EasyMock.expect(config.getInitParameter(
                            UserServlet.class.getName() + ".PrivilegedHttpPrincipals")).
                    andReturn("user1 \"user2\" user3");
            EasyMock.replay(config);
            try {
                userServlet.init(config);
                Assert.fail("Should have thrown an error");
            } catch (ExceptionInInitializerError e) {
                // expected
            }
        } catch (Exception e) {
            log.error("Unexpected", e);
            Assert.fail(e.getMessage());
        }
    }
}
