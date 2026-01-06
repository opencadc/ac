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

package ca.nrc.cadc.ac.server.web.groups;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupAlreadyExistsException;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.MemberAlreadyExistsException;
import ca.nrc.cadc.ac.ReaderException;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.WriterException;
import ca.nrc.cadc.ac.xml.GroupWriter;
import ca.nrc.cadc.auth.AuthenticationUtil;
import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Logger;
import org.opencadc.gms.GroupURI;

public class CreateAction extends InlineContentAction {
    private static final Logger log = Logger.getLogger(CreateAction.class);

    public void doAction() throws Exception {
        if (getRequestInput().groupName == null) {
            createGroup();
        } else {
            // add users to existing group
            if (getRequestInput().memberName == null) {
                throw new IllegalArgumentException("Member name not specified in create request");
            }

            Group targetGroup = groupPersistence.getGroup(getRequestInput().groupName);
            if (getRequestInput().userIDType == null) {
                addGroupMember(targetGroup, getRequestInput().memberName);
            } else {
                addUserMember(targetGroup, getRequestInput().memberName, getRequestInput().userIDType);
            }

        }
    }

    private void createGroup() throws UserNotFoundException, GroupAlreadyExistsException, GroupNotFoundException,
            IOException, WriterException, ReaderException {
        Group group = getInputGroup();

        // restriction: prevent hierarchical group names now that GroupURI allows it
        GroupURI gid = group.getID();
        String name = gid.getName();
        String[] ss = name.split("/");
        if (ss.length > 1) {
            throw new IllegalArgumentException("invalid group name (/ not permitted): " + name);
        }
        Group returnGroup = groupPersistence.addGroup(group);
        syncOutput.setHeader("Content-Type", "application/xml");
        syncOutput.setCode(200);
        GroupWriter groupWriter = new GroupWriter();
        groupWriter.write(returnGroup, syncOutput.getOutputStream());

        List<String> addedMembers = getStrings(group);
        logGroupInfo(group.getID().getName(), null, addedMembers);
    }

    private static List<String> getStrings(Group group) {
        List<String> addedMembers = null;
        if ((!group.getUserMembers().isEmpty()) || (!group.getGroupMembers().isEmpty())) {
            addedMembers = new ArrayList<>();
            for (Group gr : group.getGroupMembers()) {
                addedMembers.add(gr.getID().getName());
            }
            for (User usr : group.getUserMembers()) {
                Principal p = usr.getHttpPrincipal();   //TODO on the gms service these should be user IDs only
                if (p == null) {
                    p = usr.getX500Principal();
                }
                addedMembers.add(p.getName());
            }
        }
        return addedMembers;
    }

    private void addGroupMember(Group group, String groupMemberName) throws
            GroupNotFoundException, UserNotFoundException, GroupAlreadyExistsException {
        GroupURI toAddID = new GroupURI(serviceURI, groupMemberName);
        Group toAdd = new Group(toAddID);

        if (!group.getGroupMembers().add(toAdd)) {
            throw new GroupAlreadyExistsException(groupMemberName);
        }
        log.debug("Adding group member: " + groupMemberName);
        groupPersistence.modifyGroup(group);

        List<String> addedMembers = new ArrayList<>();
        addedMembers.add(toAdd.getID().getName());
        logGroupInfo(group.getID().getName(), null, addedMembers);
    }

    private void addUserMember(Group group, String userID, String userIDType) throws
            UserNotFoundException, MemberAlreadyExistsException, GroupNotFoundException {
        Principal userPrincipal = AuthenticationUtil.createPrincipal(userID, userIDType);

        User toAdd = new User();

        toAdd.getIdentities().add(userPrincipal);
        if (!group.getUserMembers().add(toAdd)) {
            throw new MemberAlreadyExistsException();
        }
        log.debug("Adding user member: " + userID + " of type: " + userIDType);
        groupPersistence.modifyGroup(group);

        List<String> addedMembers = new ArrayList<>();
        addedMembers.add(getUserIdForLogging(toAdd));
        logGroupInfo(group.getID().getName(), null, addedMembers);
    }
}
