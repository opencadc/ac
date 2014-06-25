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

package ca.nrc.cadc.auth.model;

public class UserDetails
{
    private String firstName;
    private String lastName;
    private String email;
    private String address;
    private String institute;
    private String city;
    private String country;

    public PersonalTitle title;
    public String telephone;
    public String fax;
    public String province;
    public String postalCode;

    public UserDetails(String firstName, String lastName, String email,
            String address, String institute, String city, String country)
    {
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        this.address = address;
        this.institute = institute;
        this.city = city;
        this.country = country;
    }

    public String getFirstName()
    {
        return firstName;
    }

    public String getLastName()
    {
        return lastName;
    }

    public String getEmail()
    {
        return email;
    }

    public String getAddress()
    {
        return address;
    }

    public String getInstitute()
    {
        return institute;
    }

    public String getCity()
    {
        return city;
    }

    public String getCountry()
    {
        return country;
    }

    public String getFax()
    {
        return fax;
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
        result = prime * result
                + ((address == null) ? 0 : address.hashCode());
        result = prime * result + ((city == null) ? 0 : city.hashCode());
        result = prime * result
                + ((country == null) ? 0 : country.hashCode());
        result = prime * result
                + ((email == null) ? 0 : email.hashCode());
        result = prime * result
                + ((firstName == null) ? 0 : firstName.hashCode());
        result = prime * result
                + ((institute == null) ? 0 : institute.hashCode());
        result = prime * result
                + ((lastName == null) ? 0 : lastName.hashCode());
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
        if (!(obj instanceof UserDetails))
        {
            return false;
        }
        UserDetails other = (UserDetails) obj;
        if (address == null)
        {
            if (other.address != null)
            {
                return false;
            }
        }
        else if (!address.equals(other.address))
        {
            return false;
        }
        if (city == null)
        {
            if (other.city != null)
            {
                return false;
            }
        }
        else if (!city.equals(other.city))
        {
            return false;
        }
        if (country == null)
        {
            if (other.country != null)
            {
                return false;
            }
        }
        else if (!country.equals(other.country))
        {
            return false;
        }
        if (email == null)
        {
            if (other.email != null)
            {
                return false;
            }
        }
        else if (!email.equals(other.email))
        {
            return false;
        }
        if (fax == null)
        {
            if (other.fax != null)
            {
                return false;
            }
        }
        else if (!fax.equals(other.fax))
        {
            return false;
        }
        if (firstName == null)
        {
            if (other.firstName != null)
            {
                return false;
            }
        }
        else if (!firstName.equals(other.firstName))
        {
            return false;
        }
        if (institute == null)
        {
            if (other.institute != null)
            {
                return false;
            }
        }
        else if (!institute.equals(other.institute))
        {
            return false;
        }
        if (lastName == null)
        {
            if (other.lastName != null)
            {
                return false;
            }
        }
        else if (!lastName.equals(other.lastName))
        {
            return false;
        }
        if (postalCode == null)
        {
            if (other.postalCode != null)
            {
                return false;
            }
        }
        else if (!postalCode.equals(other.postalCode))
        {
            return false;
        }
        if (province == null)
        {
            if (other.province != null)
            {
                return false;
            }
        }
        else if (!province.equals(other.province))
        {
            return false;
        }
        if (telephone == null)
        {
            if (other.telephone != null)
            {
                return false;
            }
        }
        else if (!telephone.equals(other.telephone))
        {
            return false;
        }
        if (title != other.title)
        {
            return false;
        }
        return true;
    }

    @Override
    public String toString()
    {
        return getClass().getSimpleName() + "[" + firstName + ", "
                + lastName + ", " + email + ", " + address + ", "
                + institute + ", " + city + ", " + country + "]";
    }
}
