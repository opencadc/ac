/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2026.                            (c) 2026.
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
 *  $Revision: 4 $
 *
 ************************************************************************
 */

package org.opencadc.ac;

import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.server.GroupPersistence;
import ca.nrc.cadc.ac.server.PluginFactory;
import ca.nrc.cadc.ac.server.web.WebUtil;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.IdentityType;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import ca.nrc.cadc.rest.InlineContentHandler;
import ca.nrc.cadc.rest.RestAction;
import java.net.URI;
import java.security.Principal;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Logger;


public abstract class AbstractAction extends RestAction {
    private static final Logger log = Logger.getLogger(AbstractAction.class);

    protected Subject privilegedSubject;
    protected GroupLogInfo logInfo = new GroupLogInfo();
    protected GroupPersistence groupPersistence;
    protected GroupsConfig config;
    protected final RequestInput requestInput = new RequestInput();
    protected URI serviceURI;

    public AbstractAction() {
    }

    @Override
    public void initAction() throws Exception {
        super.initAction();
        config = InitGroupAction.getConfig(appName);
        setPrivilegedSubject();
        setRequestInput();
        setServiceURI();
        PluginFactory pluginFactory = new PluginFactory();
        groupPersistence = pluginFactory.createGroupPersistence();
    }

    public void setGroupPersistence(GroupPersistence groupPersistence) {
        this.groupPersistence = groupPersistence;
    }

    @Override
    protected InlineContentHandler getInlineContentHandler() {
        return null;
    }


    public void setServiceURI() {
        LocalAuthority localAuthority = new LocalAuthority();
        serviceURI = localAuthority.getResourceID(Standards.GMS_GROUPS_01);
    }

    protected void logGroupInfo(String groupID, List<String> deletedMembers, List<String> addedMembers) {
        this.logInfo.groupID = groupID;
        this.logInfo.addedMembers = addedMembers;
        this.logInfo.deletedMembers = deletedMembers;
    }

    protected String getUserIdForLogging(User u) {
        if (u.getIdentities().isEmpty()) {
            throw new IllegalArgumentException("User has no identities");
        }


        Iterator<Principal> i = u.getIdentities().iterator();
        String ret = null;
        Principal next;
        while (i.hasNext()) {
            next = i.next();
            if (next instanceof HttpPrincipal) {
                return next.getName();
            }
            if (next instanceof X500Principal) {
                ret = next.getName();
            } else {
                if (ret == null) {
                    ret = next.getName();
                }
            }
        }
        return ret;
    }

    protected void setPrivilegedSubject() {
        if (config.getPrivilegedSubjects().isEmpty()) {
            return;
        }

        Subject caller = AuthenticationUtil.getCurrentSubject();
        for (Principal principal : caller.getPrincipals()) {
            if (principal instanceof X500Principal) {
                for (Subject s : config.getPrivilegedSubjects()) {
                    Set<X500Principal> x500Principals = s.getPrincipals(X500Principal.class);
                    for (X500Principal p2 : x500Principals) {
                        if (p2.getName().equalsIgnoreCase(principal.getName())) {
                            privilegedSubject = s;
                            return;
                        }
                    }
                }
            }

            if (principal instanceof HttpPrincipal) {
                for (Subject s : config.getPrivilegedSubjects()) {
                    Set<HttpPrincipal> httpPrincipals = s.getPrincipals(HttpPrincipal.class);
                    for (HttpPrincipal p2 : httpPrincipals) {
                        if (p2.getName().equalsIgnoreCase(principal.getName())) {
                            privilegedSubject = s;
                            return;
                        }
                    }
                }
            }
        }
    }

    static class RequestInput {
        String groupName;
        String memberName;
        String userIDType;
    }

    protected void setRequestInput() {
        String path = syncInput.getPath();
        requestInput.userIDType = null;  // reset to null by default
        log.debug("path: " + path);
        if (path != null) {

            String[] segments = WebUtil.getPathSegments(path);

            switch (segments.length) {
                case 0: {
                    break;
                }
                case 1: {
                    requestInput.groupName = segments[0];
                    break;
                }
                case 3: {
                    requestInput.groupName = segments[0];
                    requestInput.memberName = segments[2];
                    if (segments[1].equalsIgnoreCase("userMembers")) {
                        requestInput.userIDType = syncInput.getParameter("idType");
                        if (requestInput.userIDType == null) {
                            requestInput.userIDType = IdentityType.USERNAME.getValue(); //default (for now)
                        }
                    }
                    break;
                }
                default: {
                    throw new IllegalArgumentException("Invalid path: " + path);
                }
            }
        }
    }
}
