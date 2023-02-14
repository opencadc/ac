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

package org.opencadc.gms;

import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.cred.client.CredUtil;
import ca.nrc.cadc.net.HttpGet;
import ca.nrc.cadc.net.ResourceAlreadyExistsException;
import ca.nrc.cadc.net.ResourceNotFoundException;
import ca.nrc.cadc.reg.Capabilities;
import ca.nrc.cadc.reg.Capability;
import ca.nrc.cadc.reg.Interface;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.RegistryClient;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.net.URI;
import java.net.URL;
import java.security.AccessControlException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import javax.security.auth.Subject;
import org.apache.log4j.Logger;

/**
 * Client implementation of the IVOA Group Membership Service (GMS) specification.
 * 
 * @author pdowler
 */
public class IvoaGroupClient {
    private static final Logger log = Logger.getLogger(IvoaGroupClient.class);

    private final RegistryClient reg = new RegistryClient();
    
    public IvoaGroupClient() { 
    }
    
    /**
     * Return true if the calling user is a member of
     * the group.
     * 
     * @param group The group membership to check
     * @return true if the user is a member
     * 
     * @throws java.io.IOException local caching by registry client fails
     * @throws java.lang.InterruptedException thread interrupted
     * @throws ca.nrc.cadc.net.ResourceNotFoundException specified service not found in registry
     */
    public boolean isMember(GroupURI group) throws IOException, InterruptedException,
            ResourceNotFoundException {
        URI resourceID = group.getServiceID();
        Set<String> names = new TreeSet<>();
        names.add(group.getName());
        Set<GroupURI> mem = getMemberships(resourceID, names);
        return !mem.isEmpty();
    }
    
    /**
     * Determine group membership in a specified list of candidate groups.
     * 
     * @param uris candidate groups to check
     * @return possibly empty list of groups where the caller is a member
     * 
     * @throws java.io.IOException local caching by registry client fails
     * @throws java.lang.InterruptedException thread interrupted
     * @throws ca.nrc.cadc.net.ResourceNotFoundException specified service not found in registry
     */
    public Set<GroupURI> getMemberships(Set<GroupURI> uris) throws IOException, InterruptedException,
            ResourceNotFoundException {
        // split uris into groups with same resourceID base
        Map<URI,Set<String>> gmsMap = splitByResourceID(uris);
        Set<GroupURI> ret = new TreeSet<>();
        for (Map.Entry<URI,Set<String>> me : gmsMap.entrySet()) {
            Set<GroupURI> tmp = getMemberships(me.getKey(), me.getValue());
            ret.addAll(tmp);
        }
        return ret;
    }
    
    /**
     * Get the complete list of groups the caller belongs to
     * from the specified GMS service.
     * 
     * @param resourceID resourceID of the GMS service to query
     * @return groups the user is a member of
     * 
     * @throws java.io.IOException local caching by registry client fails
     * @throws java.lang.InterruptedException thread interrupted
     * @throws ca.nrc.cadc.net.ResourceNotFoundException specified service not found in registry
     */
    public Set<GroupURI> getMemberships(URI resourceID) throws IOException, InterruptedException,
            ResourceNotFoundException {
        return getMemberships(resourceID, null);
    }
    
    /**
     * Get a subset of groups the caller belongs to from the specified GMS service.
     * 
     * @param resourceID resourceID of the GMS service to query
     * @param groupNames optional candidate groups to check
     * @return The group memberships for the user.
     * @throws java.io.IOException local caching by registry client fails
     * @throws java.lang.InterruptedException thread interrupted
     * @throws ca.nrc.cadc.net.ResourceNotFoundException specified service not found in registry
     */
    public Set<GroupURI> getMemberships(URI resourceID, Set<String> groupNames) throws IOException, InterruptedException,
            ResourceNotFoundException {
        
        Subject cur = AuthenticationUtil.getCurrentSubject();
        AuthMethod am = AuthenticationUtil.getAuthMethod(cur);
        if (am == null || AuthMethod.ANON.equals(am)) {
            throw new UnsupportedOperationException("cannot get group memberships for anonymous");
        }
        
        Capabilities caps = reg.getCapabilities(resourceID);
        if (caps == null) {
            throw new ResourceNotFoundException("service not found in registry: " + resourceID);
        }

        Capability cap = caps.findCapability(Standards.GMS_SEARCH_10);
        if (cap == null) {
            throw new UnsupportedOperationException("service " + resourceID + " does not implement " + Standards.GMS_SEARCH_10);
        }
        
        try {
            if (!CredUtil.checkCredentials()) {
                throw new AccessControlException("delegated credentials not found");
            }
        } catch (CertificateExpiredException | CertificateNotYetValidException ex) {
            throw new AccessControlException("invalid delegated credentials: " + ex);
        }
        
        AuthMethod amc = AuthenticationUtil.getAuthMethodFromCredentials(cur);
        if (amc == null || AuthMethod.ANON.equals(amc)) {
            throw new RuntimeException("BUG: subject has credentials but type unknown");
        }
        URI securityMethod = Standards.getSecurityMethod(amc);
        Interface iface = cap.findInterface(securityMethod);
        if (iface == null) {
            throw new UnsupportedOperationException("service " + resourceID + " " + Standards.GMS_SEARCH_10
                    + " does not support auth via " + securityMethod);
        }
        URL queryURL = iface.getAccessURL().getURL();
        if (groupNames != null && !groupNames.isEmpty()) {
            StringBuilder sb = new StringBuilder(queryURL.toExternalForm());
            String sep = "?";
            for (String name : groupNames) {
                sb.append(sep).append("group=").append(name);
                sep = "&";
            }
            queryURL = new URL(sb.toString());
        }
        log.warn("queryURL: " + queryURL);
        
        Set<GroupURI> ret = new TreeSet<>();
        try {
            HttpGet query = new HttpGet(queryURL, true);
            query.prepare();

            InputStream istream = query.getInputStream();
            LineNumberReader r = new LineNumberReader(new InputStreamReader(istream));
            String line = r.readLine();
            while (line != null) {
                String name = line.trim();
                GroupURI g = new GroupURI(resourceID, name);
                ret.add(g);
                line = r.readLine();
            }
            
        } catch (ResourceAlreadyExistsException ex) {
            throw new RuntimeException("BUG: unexpected failure: " + ex, ex);
        }
        return ret;
    }
    
    private Map<URI,Set<String>> splitByResourceID(Set<GroupURI> uris) {
        Map<URI,Set<String>> ret = new TreeMap<>();
        for (GroupURI u : uris) {
            Set<String> cur = ret.get(u.getServiceID());
            if (cur == null) {
                cur = new TreeSet<>();
                ret.put(u.getServiceID(), cur);
            }
            cur.add(u.getName());
            
        }
        return ret;
    }
}
