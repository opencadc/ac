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

import java.util.UUID;

/**
 * Class that represents a numeric id. This is useful for
 * representing an internal user key reference.
 */
public class InternalID
{
    private UUID id;
    private String authority;

    /**
     * Ctor
     * @param id unique identifier
     */
    public InternalID(UUID id, String authority)
    {
        if (id == null)
        {
            throw new IllegalArgumentException("id is null");
        }
        if (authority == null || authority.isEmpty())
        {
            throw new IllegalArgumentException("authority is null or empty");
        }

        this.id = id;
        this.authority = authority;
    }

    public UUID getId()
    {
        return id;
    }

    public String getAuthority()
    {
        return authority;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode()
    {
        int prime = 31;
        int result = 1;
        result = prime * result + id.hashCode();
        result = prime * result + authority.toLowerCase().hashCode();
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
        if (!(obj instanceof InternalID))
        {
            return false;
        }
        InternalID other = (InternalID) obj;
        if (id.equals(other.id) &&
            authority.equalsIgnoreCase(other.authority))
        {
            return true;
        }
        return false;
    }

    @Override
    public String toString()
    {
        return getClass().getSimpleName() + "[" + id + "," + authority + "]";
    }

}
