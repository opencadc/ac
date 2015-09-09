package ca.nrc.cadc.ac.admin;

import org.apache.log4j.Logger;

/**
 * This class deletes the specified pending user from the LDAP server.
 * @author yeunga
 *
 */
public class Reject extends AbstractCommand 
{
    private static final Logger log = Logger.getLogger(Reject.class);

	private String userID;
	
	/**
	 * Constructor
	 * @param userID Id of the pending user to be deleted
	 */
    public Reject(final String userID)
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
