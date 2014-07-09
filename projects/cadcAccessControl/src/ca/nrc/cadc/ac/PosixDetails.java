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

/**
 * Represents the posix account details associated with a user account.
 */
public class PosixDetails implements UserDetails
{
    private long uid;
    private long gid;
    private String homeDirectory;

    /**
     * user login shell
     */
    public String loginShell;

    /**
     * 
     * @param uid
     *            posix uid
     * @param gid
     *            posix gid
     * @param homeDirectory
     *            home directory
     */
    public PosixDetails(long uid, long gid, String homeDirectory)
    {
        this.uid = uid;
        this.gid = gid;
        if (homeDirectory == null)
        {
            throw new IllegalArgumentException(
                    "null home directory in POSIX details");
        }
        this.homeDirectory = homeDirectory;
    }

    /**
     * @return the uid
     */
    public long getUid()
    {
        return uid;
    }

    /**
     * @return the gid
     */
    public long getGid()
    {
        return gid;
    }

    /**
     * @return the homeDirectory
     */
    public String getHomeDirectory()
    {
        return homeDirectory;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + (int) (gid ^ (gid >>> 32));
        result = prime * result + homeDirectory.hashCode();
        result = prime * result + (int) (uid ^ (uid >>> 32));
        return result;
    }

    /*
     * (non-Javadoc)
     * 
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
        if (!(obj instanceof PosixDetails))
        {
            return false;
        }
        PosixDetails other = (PosixDetails) obj;
        if (gid != other.gid)
        {
            return false;
        }

        if (!homeDirectory.equals(other.homeDirectory))
        {
            return false;
        }
        return true;
    }

    @Override
    public String toString()
    {
        return getClass().getSimpleName() + "[" + uid + ", " + gid + ", "
                + homeDirectory + "]";
    }

}
