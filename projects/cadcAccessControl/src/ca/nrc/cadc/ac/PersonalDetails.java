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

public class PersonalDetails implements UserDetails
{
    private String firstName;
    private String lastName;
    private String email;
    private String address;
    private String institute;
    private String city;
    private String country;

    public PersonalDetails(String firstName, String lastName, String email,
            String address, String institute, String city, String country)
    {
        if (firstName == null)
        {
            throw new IllegalArgumentException("null firstName");
        }
        if (lastName == null)
        {
            throw new IllegalArgumentException("null lastName");
        }
        if (email == null)
        {
            throw new IllegalArgumentException("null email");
        }

        if (address == null)
        {
            throw new IllegalArgumentException("null address");
        }
        if (institute == null)
        {
            throw new IllegalArgumentException("null institute");
        }
        if (city == null)
        {
            throw new IllegalArgumentException("null city");
        }
        if (country == null)
        {
            throw new IllegalArgumentException("null country");
        }
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

    /* (non-Javadoc)
     * @see ca.nrc.cadc.auth.model.UserDetails#hashCode()
     */
    @Override
    public int hashCode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + address.hashCode();
        result = prime * result + city.hashCode();
        result = prime * result + country.hashCode();
        result = prime * result + email.hashCode();
        result = prime * result + firstName.hashCode();
        result = prime * result + institute.hashCode();
        result = prime * result + lastName.hashCode();
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
        if (!(obj instanceof PersonalDetails))
        {
            return false;
        }
        PersonalDetails other = (PersonalDetails) obj;
        if (!firstName.equals(other.firstName))
        {
            return false;
        }
        if (!lastName.equals(other.lastName))
        {
            return false;
        }
        if (!email.equals(other.email))
        {
            return false;
        }
        if (!institute.equals(other.institute))
        {
            return false;
        }
        if (!address.equals(other.address))
        {
            return false;
        }
        if (!city.equals(other.city))
        {
            return false;
        }
        if (!country.equals(other.country))
        {
            return false;
        }
        return true;
    }

    /* (non-Javadoc)
     * @see ca.nrc.cadc.auth.model.UserDetails#toString()
     */
    @Override
    public String toString()
    {
        return getClass().getSimpleName() + "[" + firstName + ", "
                + lastName + ", " + email + ", " + address + ", "
                + institute + ", " + city + ", " + country + "]";
    }
}
