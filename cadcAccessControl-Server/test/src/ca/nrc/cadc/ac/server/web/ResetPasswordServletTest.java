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

import ca.nrc.cadc.ac.UserAlreadyExistsException;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.server.UserPersistence;
import ca.nrc.cadc.ac.server.ldap.LdapUserDAO;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.util.StringUtil;

import org.junit.Test;

import javax.security.auth.Subject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.security.Principal;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.List;

import static org.easymock.EasyMock.*;


public class ResetPasswordServletTest
{   
    private static final String EMAIL_ADDRESS = "email@canada.ca";
    
    public void testSubjectAndEmailAddress(final Subject subject, final String emailAddress, 
            int responseStatus) throws Exception
    {
        @SuppressWarnings("serial")
        final ResetPasswordServlet testSubject = new ResetPasswordServlet()
        {
            @Override
            Subject getSubject(final HttpServletRequest request)
            {
                return subject;
            }
        };
        
        final HttpServletRequest mockRequest =
                createMock(HttpServletRequest.class);
        final HttpServletResponse mockResponse =
                createMock(HttpServletResponse.class);
        
        expect(mockRequest.getPathInfo()).andReturn("users/CADCtest").once();
        expect(mockRequest.getMethod()).andReturn("POST").once();
        expect(mockRequest.getRemoteAddr()).andReturn("mysite.com").once();
        
        if (!StringUtil.hasText(emailAddress))
        {
            expect(mockRequest.getParameter("emailAddress")).andReturn(emailAddress).once();
        }
        
        mockResponse.setStatus(responseStatus);
        expectLastCall().once();
    
        replay(mockRequest, mockResponse);
    
        Subject.doAs(subject, new PrivilegedExceptionAction<Void>()
        {
            @Override
            public Void run() throws Exception
            {
                testSubject.doGet(mockRequest, mockResponse);
                return null;
            }
        });
    
        verify(mockRequest, mockResponse);
    }
        
    @Test
    public void testGetWithNullSubject() throws Exception
    {
        final Subject subject = null;
        testSubjectAndEmailAddress(subject, EMAIL_ADDRESS, HttpServletResponse.SC_UNAUTHORIZED);
    }
        
    @Test
    public void testGetWithEmptySubject() throws Exception
    {
        final Subject subject = new Subject();;
        testSubjectAndEmailAddress(subject, EMAIL_ADDRESS, HttpServletResponse.SC_UNAUTHORIZED);
    }
    
    public void testPrivilegedSubjectAndEmailAddress(final List<Subject> privSubjects,
            final Subject subject, int responseStatus, final String emailAddress,
            final UserPersistence<Principal> mockUserPersistence) throws Exception
    {
        @SuppressWarnings("serial")
        final ResetPasswordServlet testSubject = new ResetPasswordServlet()
        {
            @Override
            public void init() throws ServletException
            {
                privilegedSubjects = privSubjects;
                userPersistence = mockUserPersistence;
            }
            
            @Override
            protected boolean isPrivilegedSubject(final HttpServletRequest request)
            {
                if (privSubjects == null || privSubjects.isEmpty())
                {
                    return false;
                }
                else
                {
                    return true;
                }
            }
            
            @Override
            Subject getSubject(final HttpServletRequest request)
            {
                return subject;
            }
        };
        
        final HttpServletRequest mockRequest =
                createMock(HttpServletRequest.class);
        final HttpServletResponse mockResponse =
                createMock(HttpServletResponse.class);
        
        expect(mockRequest.getPathInfo()).andReturn("users/CADCtest").once();
        expect(mockRequest.getMethod()).andReturn("POST").once();
        expect(mockRequest.getRemoteAddr()).andReturn("mysite.com").once();
        
        if (privSubjects != null && !privSubjects.isEmpty())
        {
            if (mockUserPersistence == null)
            {
                expect(mockRequest.getParameter("emailAddress")).andReturn(emailAddress).once();
            }
            else
            {
                expect(mockRequest.getParameter("emailAddress")).andReturn(emailAddress).once();
            }
        }
        
        mockResponse.setStatus(responseStatus);
        expectLastCall().once();
    
        replay(mockRequest, mockResponse, mockUserPersistence);
    
        Subject.doAs(subject, new PrivilegedExceptionAction<Void>()
        {
            @Override
            public Void run() throws Exception
            {
                testSubject.init();
                testSubject.doGet(mockRequest, mockResponse);
                return null;
            }
        });
    
        verify(mockRequest, mockResponse);
    }
    
    @Test
    public void testGetWithNullPrivilegedSubjects() throws Exception
    {
        final Subject subject = new Subject();;
        subject.getPrincipals().add(new HttpPrincipal("CADCtest"));
        UserPersistence<Principal> mockUserPersistence = 
                (UserPersistence<Principal>) createMock(UserPersistence.class);
        testPrivilegedSubjectAndEmailAddress(null, subject, 
                HttpServletResponse.SC_FORBIDDEN, "", mockUserPersistence);
    }
     
    @Test
    public void testGetWithEmptyPrivilegedSubjects() throws Exception
    {
        final Subject subject = new Subject();;
        subject.getPrincipals().add(new HttpPrincipal("CADCtest"));
        UserPersistence<Principal> mockUserPersistence = 
                (UserPersistence<Principal>) createMock(UserPersistence.class);
        testPrivilegedSubjectAndEmailAddress(new ArrayList<Subject>(), subject, 
                HttpServletResponse.SC_FORBIDDEN, "", mockUserPersistence);
    }
      
    @Test
    public void testGetWithMissingEmailAddress() throws Exception
    {
        final Subject subject = new Subject();;
        subject.getPrincipals().add(new HttpPrincipal("CADCtest"));
        List<Subject> privilegedSubjects = new ArrayList<Subject>();
        privilegedSubjects.add(new Subject());
        UserPersistence<Principal> mockUserPersistence = 
                (UserPersistence<Principal>) createMock(UserPersistence.class);
        testPrivilegedSubjectAndEmailAddress(privilegedSubjects, subject, 
                HttpServletResponse.SC_BAD_REQUEST, "", mockUserPersistence);
    }
    
    @SuppressWarnings("unchecked")
    @Test
    public void testGetWithMoreThanOneUserFound() throws Exception
    {
        final Subject subject = new Subject();;
        subject.getPrincipals().add(new HttpPrincipal("CADCtest"));
        List<Subject> privilegedSubjects = new ArrayList<Subject>();
        privilegedSubjects.add(new Subject());
        UserAlreadyExistsException uaee = 
                new UserAlreadyExistsException(LdapUserDAO.EMAIL_ADDRESS_CONFLICT_MESSAGE);
        UserPersistence<Principal> mockUserPersistence = 
                (UserPersistence<Principal>) createMock(UserPersistence.class);
        expect(mockUserPersistence.getUserByEmailAddress(EMAIL_ADDRESS)).andThrow(uaee);
        testPrivilegedSubjectAndEmailAddress(privilegedSubjects, subject, 
                HttpServletResponse.SC_CONFLICT, EMAIL_ADDRESS, mockUserPersistence);
    }
    
    @SuppressWarnings("unchecked")
    @Test
    public void testGetWithNoUserFound() throws Exception
    {
        final Subject subject = new Subject();;
        subject.getPrincipals().add(new HttpPrincipal("CADCtest"));
        List<Subject> privilegedSubjects = new ArrayList<Subject>();
        privilegedSubjects.add(new Subject());
        UserNotFoundException unfe = new UserNotFoundException("User with email address ");
        UserPersistence<Principal> mockUserPersistence = 
                (UserPersistence<Principal>) createMock(UserPersistence.class);
        expect(mockUserPersistence.getUserByEmailAddress(EMAIL_ADDRESS)).andThrow(unfe);
        testPrivilegedSubjectAndEmailAddress(privilegedSubjects, subject, 
                HttpServletResponse.SC_NOT_FOUND, EMAIL_ADDRESS, mockUserPersistence);
    }
    
    @SuppressWarnings("unchecked")
    @Test
    public void testGetWithInternalServerError() throws Exception
    {
        final Subject subject = new Subject();;
        subject.getPrincipals().add(new HttpPrincipal("CADCtest"));
        List<Subject> privilegedSubjects = new ArrayList<Subject>();
        privilegedSubjects.add(new Subject());
        RuntimeException rte = new RuntimeException();
        UserPersistence<Principal> mockUserPersistence = 
                (UserPersistence<Principal>) createMock(UserPersistence.class);
        expect(mockUserPersistence.getUserByEmailAddress(EMAIL_ADDRESS)).andThrow(rte);
        testPrivilegedSubjectAndEmailAddress(privilegedSubjects, subject, 
                HttpServletResponse.SC_INTERNAL_SERVER_ERROR, EMAIL_ADDRESS, mockUserPersistence);
    }
}
