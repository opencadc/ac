package ca.nrc.cadc.ac.admin;

import java.security.AccessControlException;
import java.security.Principal;
import java.util.Collection;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.server.UserPersistence;
import ca.nrc.cadc.net.TransientException;

/**
 * This class provides a list of all active users in the LDAP server.
 * @author yeunga
 *
 */
public class List extends AbstractCommand 
{	
    private static final Logger log = Logger.getLogger(List.class);

    /**
	 * Constructor
	 */
    public List()
    {
    }
    
	@Override
	public Object run() 
	{
		try 
		{
	        final UserPersistence<Principal> userPersistence = getUserPersistence();
			Collection<User<Principal>> users = userPersistence.getUsers();
			
	        for (User<Principal> user : users)
	        {
	        	systemOut.println(user.getUserID().getName());
	        }
		} 
		catch (AccessControlException e) 
		{
            log.error(e.getMessage(), e);
		} 
		catch (TransientException e) 
		{
            String message = "Internal Transient Error: " + e.getMessage();
            log.error(message, e);
		}
		
        return null;
	}
}
