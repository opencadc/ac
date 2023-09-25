/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2023.                            (c) 2023.
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
************************************************************************
*/

package org.opencadc.auth;

import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.PosixPrincipal;
import ca.nrc.cadc.net.HttpGet;
import ca.nrc.cadc.net.ResourceAlreadyExistsException;
import ca.nrc.cadc.net.ResourceNotFoundException;
import ca.nrc.cadc.reg.Capabilities;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.RegistryClient;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URL;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.security.auth.Subject;
import org.apache.log4j.Logger;
import org.opencadc.gms.GroupURI;

/**
 * Stub to figure out API.
 * 
 * @author pdowler
 */
public class PosixMapperClient {
    private static final Logger log = Logger.getLogger(PosixMapperClient.class);

    private final URI resourceID;

    private final RegistryClient regClient = new RegistryClient();
    
    public PosixMapperClient(URI resourceID) throws IOException, ResourceNotFoundException {
        this.resourceID = resourceID;
        if (resourceID == null) {
            throw new IllegalArgumentException("resourceID cannot be null");
        }

        Capabilities caps = regClient.getCapabilities(resourceID);
        if (caps == null) {
            throw new ResourceNotFoundException("service not found in registry: " + resourceID);
        }
    }
    
    // use case: cavern needs PosixPrincipal added to the caller subject for create node
    // use case: cavern needs to recreate Subject from PosixPrincipal to output node
    // detail: StandardIdentityManager calls this to add local posix identity for caller
    // proposal: add defaultGroup to PosixPrincipal, would be returned here
    public Subject augment(Subject subject)
        throws ResourceNotFoundException, IOException, InterruptedException {
        if (subject == null) {
            throw new IllegalArgumentException("subject cannot be null");
        }

        AuthMethod authMethod = AuthenticationUtil.getAuthMethodFromCredentials(subject);
        if (authMethod == null || AuthMethod.ANON.equals(authMethod)) {
            throw new UnsupportedOperationException("cannot augment subject for an anonymous user");
        }

        URL serviceURL = regClient.getServiceURL(resourceID, Standards.POSIX_USERMAP, authMethod);
        if (serviceURL == null) {
            throw new ResourceNotFoundException("service not found for " + resourceID);
        }

        Set<PosixPrincipal> posixPrincipals = subject.getPrincipals(PosixPrincipal.class);
        Set<HttpPrincipal> httpPrincipals = subject.getPrincipals(HttpPrincipal.class);
        if (!posixPrincipals.isEmpty() && !httpPrincipals.isEmpty()) {
            return subject; //nothing to do ?????
        }

        if (posixPrincipals.isEmpty() && httpPrincipals.isEmpty()) {
            throw new IllegalArgumentException("Subject must contain either a HttpPrincipal or a PosixPrincipal");
        }

        String user = null;
        Integer uid = null;
        if (!posixPrincipals.isEmpty()) {
            uid = posixPrincipals.iterator().next().getUidNumber();
        } else {
            user = httpPrincipals.iterator().next().getName();
        }

        StringBuilder query = new StringBuilder(serviceURL.toExternalForm());
        query.append("?");
        if (user != null) {
            query.append("user=").append(user);
        } else {
            query.append("uid=").append(uid);
        }
        URL queryURL = new URL(query.toString());

        try {
            HttpGet get = new HttpGet(queryURL, true);
            get.setRequestProperty("accept", "text/tab-separated-values");
            get.prepare();

            InputStream results = get.getInputStream();
            InputStreamReader r = new InputStreamReader(results);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(results))) {
                String line = reader.readLine();
                String[] tokens = line.split("\\s");
                if (tokens.length != 3) {
                    throw new IllegalStateException(
                            String.format("error parsing query results, expected 3 values, found %s: %s",
                                    tokens.length, line));
                }
                // format - username uid gid
                String username = tokens[0];
                int userID = Integer.parseInt(tokens[1]);
                int groupID = Integer.parseInt(tokens[2]);
                
                Set<Principal> principals = new HashSet<>();
                PosixPrincipal posixPrincipal = new PosixPrincipal(userID);
                posixPrincipal.username = username;
                posixPrincipal.defaultGroup = groupID;
                principals.add(posixPrincipal);
                principals.add(new HttpPrincipal(username));
                for (Principal p : subject.getPrincipals()) {
                    if (!(p instanceof HttpPrincipal) && !(p instanceof PosixPrincipal)) {
                        principals.add(p);
                    }
                }
                return new Subject(false, principals, subject.getPublicCredentials(), subject.getPrivateCredentials());
            }
        } catch (ResourceAlreadyExistsException e) {
            throw new RuntimeException("BUG: unexpected failure: " + e, e);
        }
    }
    
    // use case: cavern uses this when caller tries to set group permissions
    // use case: skaha uses this to generate securityContext for a user container
    // detail: this may create and persist a local GID as a side effect
    public List<PosixGroup> getGID(List<GroupURI> groups)
            throws ResourceNotFoundException, IOException, InterruptedException {
        if (groups == null) {
            throw new IllegalArgumentException("groups cannot be null");
        }

        Subject subject = AuthenticationUtil.getCurrentSubject();
        AuthMethod authMethod = AuthenticationUtil.getAuthMethodFromCredentials(subject);
        if (authMethod == null || AuthMethod.ANON.equals(authMethod)) {
            throw new UnsupportedOperationException("cannot augment subject for anonymous");
        }

        URL serviceURL = regClient.getServiceURL(resourceID, Standards.POSIX_GROUPMAP, authMethod);
        if (serviceURL == null) {
            throw new ResourceNotFoundException("not found: " + resourceID);
        }

        StringBuilder query = new StringBuilder(serviceURL.toExternalForm());
        String sep = "?";
        for (GroupURI groupURI : groups) {
            query.append(sep).append("group=").append(groupURI.getURI().toASCIIString());
            sep = "&";
        }
        URL queryURL = new URL(query.toString());

        try {
            HttpGet get = new HttpGet(queryURL, true);
            get.setRequestProperty("accept", "text/tab-separated-values");
            get.prepare();

            List<PosixGroup> posixGroups = new ArrayList<>();
            InputStream results = get.getInputStream();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(results))) {
                while (reader.ready()) {
                    String line = reader.readLine();
                    String[] tokens = line.split("\\s+");
                    if (tokens.length != 2) {
                        throw new IllegalStateException(
                                String.format("error parsing query results, expected 2 values, found %s: %s",
                                        tokens.length, line));
                    }
                    GroupURI groupURI = new GroupURI(URI.create(tokens[0]));
                    Integer gid = Integer.parseInt(tokens[1]);
                    posixGroups.add(new PosixGroup(gid, groupURI));
                }
            }
            return posixGroups;
        } catch (ResourceAlreadyExistsException e) {
            throw new RuntimeException("BUG: unexpected failure: " + e, e);
        }
    }
    
    // use case: cavern uses this when reading a node from disk and output the node doc
    public List<PosixGroup> getURI(List<Integer> groups)
            throws ResourceNotFoundException, IOException, InterruptedException {
        if (groups == null) {
            throw new IllegalArgumentException("groups cannot be null");
        }

        Subject subject = AuthenticationUtil.getCurrentSubject();
        AuthMethod authMethod = AuthenticationUtil.getAuthMethodFromCredentials(subject);
        if (authMethod == null || AuthMethod.ANON.equals(authMethod)) {
            throw new UnsupportedOperationException("cannot augment subject for anonymous");
        }

        URL serviceURL = regClient.getServiceURL(resourceID, Standards.POSIX_GROUPMAP, authMethod);
        if (serviceURL == null) {
            throw new ResourceNotFoundException("not found: " + resourceID);
        }

        StringBuilder query = new StringBuilder(serviceURL.toExternalForm());
        String sep = "?";
        for (Integer gid : groups) {
            query.append(sep).append("gid=").append(gid);
            sep = "&";
        }
        URL queryURL = new URL(query.toString());

        try {
            HttpGet get = new HttpGet(queryURL, true);
            get.setRequestProperty("accept", "text/tab-separated-values");
            get.prepare();

            List<PosixGroup> posixGroups = new ArrayList<>();
            InputStream results = get.getInputStream();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(results))) {
                while (reader.ready()) {
                    String line = reader.readLine();
                    String[] tokens = line.split("\\s+");
                    if (tokens.length != 2) {
                        throw new IllegalStateException(
                                String.format("error parsing query results, expected 2 values, found %s: %s",
                                        tokens.length, line));
                    }
                    Integer gid = Integer.parseInt(tokens[0]);
                    GroupURI groupURI = new GroupURI(URI.create(tokens[1]));
                    posixGroups.add(new PosixGroup(gid, groupURI));
                }
            }
            return posixGroups;
        } catch (ResourceAlreadyExistsException e) {
            throw new RuntimeException("BUG: unexpected failure: " + e, e);
        }
    }
    
    // use case: skaha needs the complete username-uid map for user containers
    // change: adding defaultGroup and username to PosixPrincipal, all fields would be returned here
    // note: Iterator allows the client to consume the stream and process it without having to
    // store it in memory... scalable but sometimes awkward
    public Iterator<PosixPrincipal> getUserMap() {
        throw new UnsupportedOperationException();
    }
    
    // use case: skaha needs the complete groupname-gid map for user containers
    // note: Iterator allows the client to consume the stream and process it without having to
    // store it in memory... scalable but sometimes awkward
    public Iterator<PosixGroup> getGroupMap() {
        throw new UnsupportedOperationException();
    }
}
