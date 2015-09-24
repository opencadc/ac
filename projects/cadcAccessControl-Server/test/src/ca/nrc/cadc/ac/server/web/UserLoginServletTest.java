package ca.nrc.cadc.ac.server.web;

import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.AccessControlException;
import java.util.Collection;
import java.util.HashSet;

import ca.nrc.cadc.auth.AuthenticatorImpl;
import org.easymock.EasyMock;
import org.junit.Test;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.server.GroupDetailSelector;
import ca.nrc.cadc.ac.server.ldap.LdapGroupPersistence;
import ca.nrc.cadc.auth.HttpPrincipal;

import javax.security.auth.Subject;

public class UserLoginServletTest
{
    @Test
    public void getCheckCanImpersonate() throws Throwable
    {
        final AuthenticatorImpl mockAuthenticatorImpl =
            EasyMock.createMock(AuthenticatorImpl.class);

        Subject userSubject = new Subject();
        userSubject.getPrincipals().add(new HttpPrincipal("user"));
        mockAuthenticatorImpl.augmentSubject(userSubject);
        expectLastCall().once();

        Subject proxyUserSubject = new Subject();
        proxyUserSubject.getPrincipals().add(new HttpPrincipal("proxyUser"));
        mockAuthenticatorImpl.augmentSubject(proxyUserSubject);
        expectLastCall().times(2);

        Subject nonProxyUserSubject = new Subject();
        nonProxyUserSubject.getPrincipals().add(new HttpPrincipal("nonProxyUser"));
        mockAuthenticatorImpl.augmentSubject(nonProxyUserSubject);
        expectLastCall().times(2);

        Subject niUser = new Subject();
        niUser.getPrincipals().add(new HttpPrincipal("niUser"));
        mockAuthenticatorImpl.augmentSubject(niUser);
        expectLastCall().once();

        replay(mockAuthenticatorImpl);

        LoginServlet ls = new LoginServlet()
        {
            /**
             *
             */
            private static final long serialVersionUID = 1L;

//            @Override
//            protected AuthenticatorImpl getAuthenticatorImpl()
//            {
//                return mockAuthenticatorImpl;
//            }

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
                    replay(mockGp);
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

        verify(mockAuthenticatorImpl);
    }
}
