package ca.nrc.cadc.ac.admin;

import java.security.AccessControlException;
import java.security.Principal;
import java.util.Collection;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.net.TransientException;

/**
 * This class provides a list of all active or pending users in the LDAP server.
 * The users' nsaccountlocked attribute is not set. 
 * @author yeunga
 *
 */
public abstract class AbstractListUsers extends AbstractCommand 
{	
    private static final Logger log = Logger.getLogger(AbstractListUsers.class);
        
    protected abstract Collection<User<Principal>> getUsers() throws AccessControlException, TransientException;
        
	@Override
	public Object run() 
	{
		try 
		{
			Collection<User<Principal>> users = this.getUsers();
			
	        for (User<Principal> user : users)
	        {
	        	this.systemOut.println(user.getUserID().getName());
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
