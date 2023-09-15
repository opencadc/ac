package org.opencadc.posix;


import java.util.List;

public interface PosixUtil {

    PosixUtil userName(String userName);

    PosixUtil homeDir(String homeDir);

    PosixUtil groupNames(List<String> groupNames);

    PosixUtil useClient(PosixClient posixClient);

    void load() throws Exception;

    String posixId() throws Exception;

    String posixEntry() throws Exception;

    String groupEntries() throws Exception;

    String userGroupIds() throws Exception;

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

