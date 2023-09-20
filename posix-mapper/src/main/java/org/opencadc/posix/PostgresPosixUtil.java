package org.opencadc.posix;

import org.apache.log4j.Logger;
import org.opencadc.gms.GroupURI;

import java.util.ArrayList;
import java.util.List;

import static java.lang.String.format;
import static java.lang.String.valueOf;

public class PostgresPosixUtil implements PosixUtil {
    private static final Logger log = Logger.getLogger(PostgresPosixUtil.class);
    private static final String SEPARATE = ";";

    private String userName;
    private String homeDir;
    private final List<GroupURI> groupURIList = new ArrayList<>();
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
    public PosixUtil homeDir(String homeDir) {
        this.homeDir = homeDir;
        return this;
    }

    @Override
    public PosixUtil groupURIs(List<GroupURI> groupURIList) {
        this.groupURIList.clear();
        this.groupURIList.addAll(groupURIList);
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
        return format("%s:x:%s:%s::%s/%s:/sbin/nologin", this.userName, posixId, posixId, homeDir, this.userName);
    }

//    @Override
//    public String groupEntry() throws Exception {
//        List<Group> groups = user.getGroups();
//        List<String> groupEntries = new ArrayList<>();
//        String userPrivateGroupEntry = user.getUsername() + ":x:" + user.getUid() + ":" + user.getUsername();
//        groupEntries.add(userPrivateGroupEntry);
//        for (Group group : groups) {
//            List<User> userPerGroup = posixClient.getUsersForGroup(group.getGid());
//            String concatenatedUserName = userPerGroup
//                    .stream()
//                    .map(User::getUsername)
//                    .reduce((i, j) -> i + "," + j)
//                    .orElse("");
//            String entry = group.getGroupURI() + ":x" + ":" + group.getGid() + ":" + concatenatedUserName;
//            groupEntries.add(entry);
//        }
//        return groupEntries.stream().reduce((i, j) -> i + SEPARATE + j).orElse("");
//    }
}
