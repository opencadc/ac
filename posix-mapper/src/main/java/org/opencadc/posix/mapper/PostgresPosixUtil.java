package org.opencadc.posix.mapper;


import static java.lang.String.format;
import static java.lang.String.valueOf;

public class PostgresPosixUtil implements PosixUtil {
    private String userName;
    private PosixClient posixClient;
    private User user;

    @Override
    public PosixUtil userName(String userName) {
        this.userName = userName;
        return this;
    }

    @Override
    public PosixUtil user(User user) {
        this.user = user;
        return this;
    }

    @Override
    public PosixUtil useClient(PosixClient posixClient) {
        this.posixClient = posixClient;
        return this;
    }

    @Override
    public void load() throws Exception {
        if (posixClient.userExists(userName)) {
            user = posixClient.getUser(userName);
        } else {
            user = new User(userName);
            posixClient.saveUser(user);
        }
        posixClient.updateUser(user);
    }

    @Override
    public String posixId() {
        return valueOf(user.getUid());
    }

    @Override
    public String posixEntry() {
        String posixId = posixId();
        return format("%s:x:%s:%s:::", this.userName, posixId, posixId);
    }
}
