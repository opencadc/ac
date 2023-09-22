package org.opencadc.posix.mapper;

import org.opencadc.gms.GroupURI;
import org.opencadc.posix.mapper.web.group.GroupWriter;
import org.opencadc.posix.mapper.web.user.UserWriter;

import java.util.List;

public interface PosixClient {
    default boolean userExists(String userId) throws Exception {
        return getUser(userId) != null;
    }

    User getUser(String userId) throws Exception;

    User saveUser(User user) throws Exception;

    User updateUser(User user) throws Exception;

    Group getGroup(GroupURI groupURI) throws Exception;

    Group saveGroup(Group group) throws Exception;

    boolean groupExist(GroupURI groupURI) throws Exception;

    List<User> getUsers() throws Exception;

    /**
     * Write out all the User mappings to the given writer.  It is the responsibility of the implementation to
     * ensure Users are created.
     * @param writer        The Writer to write to.
     * @param usernames     Usernames to constrain.
     * @throws Exception    If Users cannot be obtained, or written.
     */
    void writeUsers(UserWriter writer, String[] usernames) throws Exception;

    /**
     * Write out all the Group mappings to the given writer.  It is the responsibility of the implementation to
     * ensure Groups exist if so desired.
     *
     * @param writer        The Writer to write to.
     * @param groupURIConstraints     Constrain the results to the provided groupURIs.
     * @param gidConstraints     Constrain the results to the provided groupURIs.
     * @throws Exception    If Groups cannot be obtained, or written.
     */
    void writeGroups(GroupWriter writer, GroupURI[] groupURIConstraints, Integer[] gidConstraints)
            throws Exception;
}
