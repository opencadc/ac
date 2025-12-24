/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2014.                            (c) 2014.
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
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.server.PluginFactory;
import ca.nrc.cadc.ac.server.UserPersistence;
import ca.nrc.cadc.auth.AuthenticationUtil;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Logger;

public class DeleteAction extends AbstractAction {
    private static final Logger log = Logger.getLogger(DeleteAction.class);

    public void doAction() throws GroupNotFoundException, UserNotFoundException {
        if (getRequestInput().groupName == null || getRequestInput().groupName.trim().isEmpty()) {
            throw new IllegalArgumentException("Group name is required");
        }

        Group targetGroup = groupPersistence.getGroup(getRequestInput().groupName);
        if (getRequestInput().memberName == null) {
            groupPersistence.deleteGroup(getRequestInput().groupName);
            if ((!targetGroup.getUserMembers().isEmpty()) || (!targetGroup.getGroupMembers().isEmpty())) {
                this.logInfo.deletedMembers = new ArrayList<>();
                for (Group gr : targetGroup.getGroupMembers()) {
                    this.logInfo.deletedMembers.add(gr.getID().getName());
                }
                for (User usr : targetGroup.getUserMembers()) {
                    this.logInfo.deletedMembers.add(usr.getHttpPrincipal().getName());
                }
            }
        } else {
            if (getRequestInput().userIDType == null) {
                removeGroupMember(targetGroup, getRequestInput().memberName);
            } else {
                removeUserMember(targetGroup, getRequestInput().memberName, getRequestInput().userIDType);
            }
        }
    }

    private void removeGroupMember(Group group, String memberName) throws UserNotFoundException, GroupNotFoundException {
        log.debug("group member count: " + group.getGroupMembers().size());
        if (!group.getGroupMembers().removeIf(g -> g.getID().getName().equals(memberName))) {
            throw new GroupNotFoundException("Group member not found: " + memberName);
        }
        log.debug("removed group member: " + memberName);
        groupPersistence.modifyGroup(group);
        List<String> deletedMembers = new ArrayList<>();
        deletedMembers.add(memberName);
        logGroupInfo(group.getID().getName(), deletedMembers, null);
    }

    private void removeUserMember(Group group, String memberName, String userIDType) throws UserNotFoundException, GroupNotFoundException {
        log.debug("user member count: " + group.getUserMembers().size());
        Principal userPrincipal = AuthenticationUtil.createPrincipal(memberName, userIDType);

        User user = getUserPersistence().getAugmentedUser(userPrincipal, false);
        if (!group.getUserMembers().removeIf(u -> u.equals(user))) {
            throw new UserNotFoundException("User member not found: " + memberName);
        }
        log.debug("removed user member: " + memberName);
        groupPersistence.modifyGroup(group);
        List<String> deletedMembers = new ArrayList<>();
        deletedMembers.add(memberName);
        logGroupInfo(group.getID().getName(), deletedMembers, null);
    }

    protected UserPersistence getUserPersistence() {
        PluginFactory pluginFactory = new PluginFactory();
        return pluginFactory.createUserPersistence();
    }

}
