package ca.nrc.cadc.ac.admin;

import java.security.AccessControlException;
import java.security.Principal;
import java.util.Collection;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.server.UserPersistence;
import ca.nrc.cadc.net.TransientException;

/**
 * This class provides a list of all active or pending users in the LDAP server.
 * The users' nsaccountlocked attribute is not set. 
 * @author yeunga
 *
 */
public class ListPendingUsers extends AbstractListUsers 
{	
    private static final Logger log = Logger.getLogger(ListPendingUsers.class);
    
    /**
	 * Constructor
	 */
    public ListPendingUsers()
    {
    }
    
    protected Collection<User<Principal>> getUsers() 
    		throws AccessControlException, TransientException
    {
        final UserPersistence<Principal> userPersistence = getUserPersistence();
    	//return userPersistence.getPendingUsers();
        return null;
    }
}
