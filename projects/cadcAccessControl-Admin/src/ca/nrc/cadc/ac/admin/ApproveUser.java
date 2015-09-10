package ca.nrc.cadc.ac.admin;

import org.apache.log4j.Logger;

/**
 * This class approves the specified pending user by changing the user
 * from a pending user to an active user in the LDAP server.
 * @author yeunga
 *
 */
public class ApproveUser extends AbstractCommand 
{
    private static final Logger log = Logger.getLogger(ApproveUser.class);

	private String userID;
	
	/**
	 * Constructor
	 * @param userID Id of the pending user to be approved
	 */
    public ApproveUser(final String userID)
    {
    	this.userID = userID;
    }
    
	@Override
	public Object run() 
	{
		// TODO Auto-generated method stub
        return new Object();
	}
}
