/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2014.                            (c) 2014.
 * National Research Council            Conseil national de recherches
 * Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 * All rights reserved                  Tous droits reserves
 *
 * NRC disclaims any warranties         Le CNRC denie toute garantie
 * expressed, implied, or statu-        enoncee, implicite ou legale,
 * tory, of any kind with respect       de quelque nature que se soit,
 * to the software, including           concernant le logiciel, y com-
 * without limitation any war-          pris sans restriction toute
 * ranty of merchantability or          garantie de valeur marchande
 * fitness for a particular pur-        ou de pertinence pour un usage
 * pose.  NRC shall not be liable       particulier.  Le CNRC ne
 * in any event for any damages,        pourra en aucun cas etre tenu
 * whether direct or indirect,          responsable de tout dommage,
 * special or general, consequen-       direct ou indirect, particul-
 * tial or incidental, arising          ier ou general, accessoire ou
 * from the use of the software.        fortuit, resultant de l'utili-
 *                                      sation du logiciel.
 *
 *
 * @author adriand
 * 
 * @version $Revision: $
 * 
 * 
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */



package ca.nrc.cadc.ac;

import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

public class User<T extends Principal>
{
    private T userID;

    private Set<Principal> principals = new HashSet<Principal>();
    
    public Set<UserDetails> details = new HashSet<UserDetails>();
    
    
    public User(final T userID)
    {
        if(userID == null)
        {
            throw new IllegalArgumentException("null userID");
        }
        this.userID = userID;
    }
    
    
    public Set<Principal> getPrincipals()
    {
        return principals;
    }
    
    public T getUserID()
    {
        return userID;
    }


    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + userID.hashCode();
        return result;
    }


    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(Object obj)
    {
        if (this == obj)
        {
            return true;
        }
        if (obj == null)
        {
            return false;
        }
        if (getClass() != obj.getClass())
        {
            return false;
        }
        User<?> other = (User<?>) obj;
        if (!userID.equals(other.userID))
        {
            return false;
        }
        return true;
    }
    
    @Override
    public String toString()
    {
        return getClass().getSimpleName() + "[" + userID.getName() + "]";
    }
    
}
