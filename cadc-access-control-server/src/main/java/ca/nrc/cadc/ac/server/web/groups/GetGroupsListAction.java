/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ca.nrc.cadc.ac.server.web.groups;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.xml.GroupListWriter;
import ca.nrc.cadc.ac.xml.GroupWriter;
import java.security.AccessControlException;
import java.util.ArrayList;
import java.util.Collection;
import org.apache.log4j.Logger;

/**
 *
 * @author bertocco
 */
public class GetGroupsListAction  extends AbstractGroupAction {
    

    private static final Logger log = Logger.getLogger(GetGroupsListAction.class);

    GetGroupsListAction()
    {
        super();
    }

    public void doAction() throws Exception
    {
     
        Collection<String> groupNames = groupPersistence.getGroupNames();
        Collection<Group> groups = new ArrayList<Group>();
        log.debug("Found " + groupNames.size() + " group names");

        Group group = new Group();
        syncOut.setHeader("Content-Type", "application/xml");
        GroupListWriter groupListWriter = new GroupListWriter();
        for (final String currentGroup : groupNames)
        {
            try {
                group = groupPersistence.getGroup(currentGroup);
                groups.add(group);
            } catch (AccessControlException ace) {
                // The user can read only groups of which is member or owner
                log.info("User can not read group " + currentGroup);
            }
        }
        groupListWriter.write(groups, syncOut.getWriter());
    }
    
}
