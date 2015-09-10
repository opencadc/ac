package ca.nrc.cadc.ac.admin;

import java.security.Principal;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.server.UserPersistence;

/**
 * This class provides details of the specified user in the LDAP server.
 * @author yeunga
 *
 */
public class ViewUser extends AbstractCommand 
{
    private static final Logger log = Logger.getLogger(ViewUser.class);

	private String userID;
	
	/**
	 * Constructor
	 * @param userID Id of the user to provide details for
	 */
    public ViewUser(final String userID)
    {
    	this.userID = userID;
    }
    
	@Override
	public Object run() 
	{
        final UserPersistence<Principal> userPersistence = getUserPersistence();
		//User<Principal> user = userPersistence.getUser(arg0);
        return null;
	}
}
