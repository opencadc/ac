package ca.nrc.cadc.ac.server.web.users;

import java.security.AccessControlException;
import java.util.Collection;
import java.util.HashSet;

import org.easymock.EasyMock;
import org.junit.Test;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.server.GroupDetailSelector;
import ca.nrc.cadc.ac.server.ldap.LdapGroupPersistence;
import ca.nrc.cadc.auth.HttpPrincipal;

import static org.junit.Assert.fail;
import static org.junit.Assert.assertTrue;

public class UserLoginServletTest
{
    @Test
    public void getCheckCanImpersonate() throws Throwable
    {
        LoginServlet ls = new LoginServlet()
        {
            /**
             * 
             */
            private static final long serialVersionUID = 1L;

            @Override
            protected LdapGroupPersistence<HttpPrincipal> getLdapGroupPersistence()
            {
                proxyGroup = "proxyGroup";
                nonImpersonGroup = "niGroup";
                Collection<Group> proxyGroups = new HashSet<Group>();
                proxyGroups.add(new Group(proxyGroup));
                Collection<Group> niGroups = new HashSet<Group>();
                niGroups.add(new Group(nonImpersonGroup));
                // mock returns a shell instance
                @SuppressWarnings("unchecked")
                LdapGroupPersistence<HttpPrincipal> mockGp = 
                    (LdapGroupPersistence<HttpPrincipal>)EasyMock
                        .createMock(LdapGroupPersistence.class);
                mockGp.setDetailSelector(new GroupDetailSelector()
                {
                    @Override
                    public boolean isDetailedSearch(Group g, Role r)
                    {
                        return false;
                    }
                });
                try
                {
                    EasyMock.expect(
                            mockGp.getGroups(new HttpPrincipal("proxyUser"),
                                    Role.MEMBER, proxyGroup)).andReturn(
                            proxyGroups);
                    EasyMock.expect(
                            mockGp.getGroups(new HttpPrincipal("nonProxyUser"),
                                    Role.MEMBER, proxyGroup)).andReturn(
                            new HashSet<Group>());
                    EasyMock.expect(
                            mockGp.getGroups(new HttpPrincipal("user"),
                                    Role.MEMBER, nonImpersonGroup)).andReturn(
                            new HashSet<Group>());
                    EasyMock.expect(
                            mockGp.getGroups(new HttpPrincipal("niUser"),
                                    Role.MEMBER, nonImpersonGroup)).andReturn(
                            niGroups);
                    EasyMock.replay(mockGp);
                } catch (Exception e)
                {
                    throw new RuntimeException(e);
                }
                return mockGp;
            }
        };
        // proxyUser can impersonate user
        ls.checkCanImpersonate("user", "proxyUser");
        // nonProxyUser cannot impersonate
        try
        {
            ls.checkCanImpersonate("user", "nonProxyUser");
            fail("AccessControlException expected");
        } catch (AccessControlException ex)
        {
            assertTrue(ex.getMessage().contains("not allowed to impersonate"));
        }
        // niUser cannot be impersonated
        try
        {
            ls.checkCanImpersonate("niUser", "proxyUser");
            fail("AccessControlException expected");
        } catch (AccessControlException ex)
        {
            assertTrue(ex.getMessage().contains("non impersonable"));
        }
        // nonProxyUser cannot impersonate and niUser cannot be impersonated
        try
        {
            ls.checkCanImpersonate("niUser", "nonProxyUser");
            fail("AccessControlException expected");
        } catch (AccessControlException ex)
        {
            assertTrue(ex.getMessage().contains("not allowed to impersonate"));
        }
    }
}
