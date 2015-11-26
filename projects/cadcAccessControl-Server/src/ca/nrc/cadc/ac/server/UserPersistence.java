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
package ca.nrc.cadc.ac.server;

import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserAlreadyExistsException;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.UserRequest;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.net.TransientException;

import java.security.AccessControlException;
import java.security.Principal;
import java.util.Collection;

public interface UserPersistence<T extends Principal>
{

    /**
     * Call if this object is to be shut down.
     */
    void destroy();

    /**
     * Add the user to the active users tree.
     *
     * @param user      The user request to put into the active users tree.
     *
     * @throws TransientException If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     * @throws ca.nrc.cadc.ac.UserAlreadyExistsException
     */
    void addUser(UserRequest<T> user)
        throws TransientException, AccessControlException,
        UserAlreadyExistsException;

    /**
     * Add the user to the pending users tree.
     *
     * @param user      The user request to put into the pending users tree.
     *
     * @throws TransientException If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     * @throws ca.nrc.cadc.ac.UserAlreadyExistsException
     */
    void addPendingUser(UserRequest<T> user)
        throws TransientException, AccessControlException,
        UserAlreadyExistsException;

    /**
     * Get the user specified by userID from the active users tree.
     *
     * @param userID The userID.
     *
     * @return User instance.
     *
     * @throws UserNotFoundException when the user is not found.
     * @throws TransientException If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    User<T> getUser(T userID)
        throws UserNotFoundException, TransientException,
        AccessControlException;

    /**
     * Get the user specified by userID whose account is pending approval.
     *
     * @param userID The userID.
     *
     * @return User instance.
     *
     * @throws UserNotFoundException when the user is not found.
     * @throws TransientException If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    User<T> getPendingUser(T userID)
        throws UserNotFoundException, TransientException,
        AccessControlException;

    /**
     * Get the user specified by userID with all of the users identities.
     *
     * @param userID The userID.
     *
     * @return User instance.
     *
     * @throws UserNotFoundException when the user is not found.
     * @throws TransientException If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    User<T> getAugmentedUser(T userID)
        throws UserNotFoundException, TransientException,
        AccessControlException;

    /**
     * Get all user names from the active users tree.
     *
     * @return A collection of strings.
     * @throws TransientException If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    Collection<User<Principal>> getUsers()
            throws TransientException, AccessControlException;

    /**
     * Get all user names from the pending users tree.
     *
     * @return A collection of strings.
     * @throws TransientException If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    Collection<User<Principal>> getPendingUsers()
        throws TransientException, AccessControlException;

    /**
     * Move the pending user specified by userID from the
     * pending users tree to the active users tree.
     *
     * @param userID      The userID.
     *
     * @return User instance.
     *
     * @throws UserNotFoundException when the user is not found.
     * @throws TransientException If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    User<T> approvePendingUser(T userID)
        throws UserNotFoundException, TransientException,
        AccessControlException;

    /**
     * Update the user specified by userID in the active users tree.
     *
     * @param user      The user instance to modify.
     *
     * @return User instance.
     *
     * @throws UserNotFoundException when the user is not found.
     * @throws TransientException If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    User<T> modifyUser(User<T> user)
        throws UserNotFoundException, TransientException,
               AccessControlException;

    /**
     * Delete the user specified by userID from the active users tree.
     *
     * @param userID The userID.
     *
     * @throws UserNotFoundException when the user is not found.
     * @throws TransientException If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    void deleteUser(T userID)
        throws UserNotFoundException, TransientException,
               AccessControlException;

    /**
     * Delete the user specified by userID from the pending users tree.
     *
     * @param userID The userID.
     *
     * @throws UserNotFoundException when the user is not found.
     * @throws TransientException If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    void deletePendingUser(T userID)
        throws UserNotFoundException, TransientException,
               AccessControlException;

    /**
     * Attempt to login the specified user.
     *
     * @param userID The userID.
     * @param password The password.
     *
     * @return Boolean
     *
     * @throws UserNotFoundException when the user is not found.
     * @throws TransientException If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    Boolean doLogin(String userID, String password)
        throws UserNotFoundException, TransientException,
        AccessControlException;

    /**
     * Update a user's password. The given user and authenticating user must match.
     *
     * @param userID
     * @param oldPassword   current password.
     * @param newPassword   new password.
     * @throws UserNotFoundException If the given user does not exist.
     * @throws TransientException   If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    void setPassword(HttpPrincipal userID, String oldPassword, String newPassword)
        throws UserNotFoundException, TransientException, AccessControlException;

}
