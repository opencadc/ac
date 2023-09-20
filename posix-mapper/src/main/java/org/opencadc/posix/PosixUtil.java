package org.opencadc.posix;


import org.opencadc.gms.GroupURI;

import java.util.List;

public interface PosixUtil {

    PosixUtil userName(String userName);

    PosixUtil user(User user);

    PosixUtil homeDir(String homeDir);

    PosixUtil groupURIs(List<GroupURI> groupURIList);

    PosixUtil useClient(PosixClient posixClient);

    void load() throws Exception;

    String posixId() throws Exception;

    String posixEntry() throws Exception;

//    String groupEntry() throws Exception;

    /**
     * Utility method so constructors can validate arguments.
     *
     * @param caller class doing test
     * @param name field name being checked
     * @param test object to test
     * @throws IllegalArgumentException if the value is invalid
     */
    static void assertNotNull(Class<?> caller, String name, Object test)
            throws IllegalArgumentException {
        if (test == null) {
            throw new IllegalArgumentException("invalid " + caller.getSimpleName() + "." + name + ": null");
        }
    }
}

