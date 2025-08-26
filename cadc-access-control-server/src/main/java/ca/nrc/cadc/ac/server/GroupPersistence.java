/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2019.                            (c) 2019.
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

package ca.nrc.cadc.ac.server;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupAlreadyExistsException;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.net.TransientException;
import java.security.AccessControlException;
import java.util.Collection;
import java.util.SortedSet;
import org.opencadc.auth.PosixGroup;

public interface GroupPersistence {
    /**
     * Call if this object is to be shut down.
     */
    void destroy();

    /**
     * Get all group names.
     *
     * @return A collection of strings.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    Collection<PosixGroup> getGroupNames()
            throws TransientException, AccessControlException;

    /**
     * Get the group with the given Group ID.
     *
     * @param groupID The Group ID.
     * @return A Group instance
     * @throws GroupNotFoundException If the group was not found.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    Group getGroup(String groupID)
            throws GroupNotFoundException, TransientException,
            AccessControlException;

    /**
     * Get the group with the given Group ID and optional permission check.
     * Normal usage should do permission checks but if the caller has priviledged
     * access (see GroupServlet) then permission check can be disabled.
     *
     * @param groupName         the group ID
     * @param doPermissionCheck normally true, false for priviledged caller
     * @return the target group
     * @throws GroupNotFoundException  If the group was not found.
     * @throws TransientException      If a temporary, unexpected problem occurred.
     * @throws AccessControlException  If the operation is not permitted for user.
     */
    Group getGroup(String groupName, boolean doPermissionCheck)
            throws GroupNotFoundException, TransientException, AccessControlException;

    /**
     * Creates the group.
     *
     * @param group The group to create
     * @return A Group instance
     * @throws GroupAlreadyExistsException If a group with the same ID already
     *                                     exists.
     * @throws TransientException          If an temporary, unexpected problem occurred.
     * @throws AccessControlException      If the operation is not permitted.
     * @throws UserNotFoundException       If owner or a member not valid user.
     * @throws GroupNotFoundException      if one of the groups in group members or
     *                                     group admins does not exist in the server.
     */
    Group addGroup(Group group)
            throws GroupAlreadyExistsException, TransientException,
            AccessControlException, UserNotFoundException,
            GroupNotFoundException;

    /**
     * Deletes the group.
     *
     * @param groupID The Group ID.
     * @throws GroupNotFoundException If the group was not found.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    void deleteGroup(String groupID)
            throws GroupNotFoundException, TransientException,
            AccessControlException;

    /**
     * Modify the given group.
     *
     * @param group The group to update.
     * @return A Group instance
     * @throws GroupNotFoundException If the group was not found.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     * @throws UserNotFoundException  If owner or group members not valid users.
     */
    Group modifyGroup(Group group)
            throws GroupNotFoundException, TransientException,
            AccessControlException, UserNotFoundException;

    /**
     * Obtain a Collection of Groups that fit the given query.
     *
     * @param role    Role of the user, either owner, member, or read/write.
     * @param groupID The Group ID.
     * @return Collection of Groups matching the query, or empty Collection.
     * Never null.
     * @throws UserNotFoundException                 If owner or group members not valid users.
     * @throws ca.nrc.cadc.ac.GroupNotFoundException If the group was not found.
     * @throws TransientException                    If a temporary, unexpected problem occurred.
     * @throws AccessControlException                If the operation is not permitted.
     */
    Collection<Group> getGroups(Role role, String groupID)
            throws UserNotFoundException, GroupNotFoundException,
            TransientException, AccessControlException;

    /**
     * Get a sorted set of distinct email addresses for all members
     * of the given group. Emails are sorted in ascending order.
     *
     * @param groupName The group name.
     * @return A sorted set of email address.
     * @throws GroupNotFoundException If the group was not found.
     * @throws TransientException     If a temporary unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    SortedSet<String> getMemberEmailsForGroup(String groupName)
            throws GroupNotFoundException, TransientException, AccessControlException;
}
