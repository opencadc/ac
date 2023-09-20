package org.opencadc.posix;

import org.opencadc.gms.GroupURI;
import org.opencadc.posix.web.group.GroupWriter;
import org.opencadc.posix.web.user.UserWriter;

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
     * Write out all the User mappings to the given writer.
     * @param writer        The Writer to write to.
     * @throws Exception    If Users cannot be obtained, or written.
     */
    void writeUsers(UserWriter writer) throws Exception;

    /**
     * Write out all the Group mappings to the given writer.
     * @param writer        The Writer to write to.
     * @throws Exception    If Groups cannot be obtained, or written.
     */
    void writeGroups(GroupWriter writer) throws Exception;
}
