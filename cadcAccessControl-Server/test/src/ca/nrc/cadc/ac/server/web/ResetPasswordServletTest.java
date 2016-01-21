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

import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.server.ACScopeValidator;
import ca.nrc.cadc.ac.server.UserPersistence;
import ca.nrc.cadc.auth.DelegationToken;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.util.RsaSignatureGenerator;
import ca.nrc.cadc.util.StringUtil;

import org.junit.Test;

import javax.security.auth.Subject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.File;
import java.io.PrintWriter;
import java.io.Writer;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.TimeZone;

import static org.easymock.EasyMock.*;


public class ResetPasswordServletTest
{   
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
    public void testGetDelegationTokenWithNullSubject() throws Exception
    {
        final Subject subject = null;
        testSubjectAndEmailAddress(subject, "testEmail@canada.ca", HttpServletResponse.SC_UNAUTHORIZED);
    }
        
    @Test
    public void testGetDelegationTokenWithEmptySubject() throws Exception
    {
        final Subject subject = new Subject();;
        testSubjectAndEmailAddress(subject, "email@canada.ca", HttpServletResponse.SC_UNAUTHORIZED);
    }
       
    @Test
    public void testGetDelegationTokenWithMissingEmailAddress() throws Exception
    {
        final Subject subject = new Subject();;
        subject.getPrincipals().add(new HttpPrincipal("CADCtest"));
        testSubjectAndEmailAddress(subject, "", HttpServletResponse.SC_BAD_REQUEST);
    }

    /**
     * Return the complete name of the directory where key files are to be 
     * created so that the RsaSignature classes can find it.
     * @return
     */
    private String getCompleteKeysDirectoryName() throws Exception
    {
        URL classLocation = 
                RsaSignatureGenerator.class.getResource(
                        RsaSignatureGenerator.class.getSimpleName() + ".class");
        if (!"file".equalsIgnoreCase(classLocation.getProtocol()))
        {
            throw new 
            IllegalStateException("SignatureUtil class is not stored in a file.");
        }

        File classPath = new File(URLDecoder.decode(classLocation.getPath(),
                                                    "UTF-8")).getParentFile();
        String packageName = RsaSignatureGenerator.class.getPackage().getName();
        String packageRelPath = packageName.replace('.', File.separatorChar);

        String dir = classPath.getAbsolutePath().
                substring(0, classPath.getAbsolutePath().indexOf(packageRelPath));
        
        if (dir == null)
        {
            throw new RuntimeException("Cannot find the class directory");
        }
        return dir;
    }
    
    private void generateKeys() throws Exception
    {
        String directory = getCompleteKeysDirectoryName();
        RsaSignatureGenerator.genKeyPair(directory);
    }
    
    @Test
    public void testResetPasswordWithInternalServerError() throws Exception
    {
        DelegationToken dt = null;
        
        final String emailAddress = "email@canada.ca";
        HttpPrincipal userID = new HttpPrincipal("CADCtest");
        
        final UserPersistence<Principal> mockUserPersistence =
                createMock(UserPersistence.class);
        mockUserPersistence.getUserByEmailAddress(emailAddress);
        expectLastCall().andThrow(new RuntimeException());

        final Subject subject = new Subject();
        subject.getPrincipals().add(userID);
    
        @SuppressWarnings("serial")
        final ResetPasswordServlet testSubject = new ResetPasswordServlet()
        {
            @Override
            public void init(final ServletConfig config) throws ServletException
            {
                super.init();

                userPersistence = mockUserPersistence;
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
        expect(mockRequest.getParameter("emailAddress")).andReturn(emailAddress).once();
    
        mockResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        expectLastCall().once();
    
        replay(mockRequest, mockResponse, mockUserPersistence);
    
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
}
