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

package ca.nrc.cadc.ac.server;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.server.impl.GroupPersistenceImpl;
import ca.nrc.cadc.net.HttpTransfer;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import ca.nrc.cadc.rest.InlineContentHandler;
import ca.nrc.cadc.rest.RestAction;
import java.io.PrintWriter;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.apache.log4j.Logger;
import org.opencadc.auth.PosixGroup;
import org.opencadc.gms.GroupURI;

/**
 * Implement the http://www.opencadc.org/std/posix#group-mapping-1.0 endpoint.
 * 
 * @author pdowler
 */
public class GetGroupMapAction extends RestAction {
    private static final Logger log = Logger.getLogger(GetGroupMapAction.class);

    public static final String CONTENT_TYPE_TSV = "text/tab-separated-values";
    
    private final URI gmsResourceID;
    
    public GetGroupMapAction() { 
        LocalAuthority loc = new LocalAuthority();
        this.gmsResourceID = loc.getServiceURI(Standards.GMS_SEARCH_10.toASCIIString());
    }

    @Override
    protected InlineContentHandler getInlineContentHandler() {
        return null;
    }

    @Override
    public void doAction() throws Exception {
        
        String accept = syncInput.getHeader("accept");
        boolean tsv = CONTENT_TYPE_TSV.equals(accept);
        
        GroupPersistenceImpl groupPersistence = new GroupPersistenceImpl();
        
        List<String> groupNameSubset = null;
        List<String> groupParams = syncInput.getParameters("group");
        if (groupParams != null && !groupParams.isEmpty()) {
            groupNameSubset = new ArrayList<>(groupParams.size());
            for (String s : groupParams) {
                GroupURI guri = new GroupURI(new URI(s));
                if (!guri.getServiceID().equals(gmsResourceID)) {
                    throw new IllegalArgumentException("invalid group (non-local): " + s);
                }
                groupNameSubset.add(guri.getName());
            }
        } 

        List<Integer> gidNameSubset = null;
        List<String> gidParams = syncInput.getParameters("gid");
        if (gidParams != null && !gidParams.isEmpty()) {
            gidNameSubset = new ArrayList<>();
            for (String s : gidParams) {
                Integer gid = Integer.valueOf(s);
                gidNameSubset.add(gid);
            }
        }

        Collection<PosixGroup> groups = groupPersistence.getGroupNames(groupNameSubset, gidNameSubset);

        log.debug("found: "  + groups.size() + " matching groups");
        if (tsv) {
            syncOutput.setHeader(HttpTransfer.CONTENT_TYPE, CONTENT_TYPE_TSV);
        } else {
            syncOutput.setHeader(HttpTransfer.CONTENT_TYPE, "text/plain");
        }
        syncOutput.setCode(200);
        PrintWriter w = new PrintWriter(syncOutput.getOutputStream());
        for (PosixGroup pg : groups) {
            if (tsv) {
                w.println(pg.getGroupURI().getURI().toASCIIString() + "\t" + pg.getGID());
            } else {
                w.println(pg.getGroupURI().getName() + ":x:" + pg.getGID() + ":");
            }
        }
        w.close();
    }
}
