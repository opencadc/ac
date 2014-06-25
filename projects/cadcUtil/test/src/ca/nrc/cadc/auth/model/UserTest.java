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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.junit.Test;

import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;

public class UserTest
{
    private static Logger log = Logger.getLogger(UserTest.class);

    @Test
    public void simpleEqualityTests() throws Exception
    {

        User<HttpPrincipal> user1 = new User<HttpPrincipal>(
                new HttpPrincipal("user1"));
        User<HttpPrincipal> user2 = user1;
        assertEquals(user1, user2);
        assertEquals(user1.hashCode(), user2.hashCode());

        user2 = new User<HttpPrincipal>(new HttpPrincipal("user1"));
        assertEquals(user1, user2);
        assertEquals(user1.hashCode(), user2.hashCode());

        user1.userDetails = new UserDetails("Joe", "Raymond",
                "jr@email.com", "123 Street", "CADC", "Victoria", "CA");
        assertFalse(user1.equals(user2));
        assertEquals(user1.hashCode(), user2.hashCode());

        user2.userDetails = user1.userDetails;
        assertEquals(user1, user2);
        assertEquals(user1.hashCode(), user2.hashCode());

        User<X500Principal> user3 = new User<X500Principal>(
                new X500Principal("cn=aaa,ou=ca"));
        User<HttpPrincipal> user4 = new User<HttpPrincipal>(
                new HttpPrincipal("cn=aaa,ou=ca"));
        assertFalse(user3.equals(user4));
        assertFalse(user3.hashCode() == user4.hashCode());

        user1.getPrincipals().add(new X500Principal("cn=aaa,ou=ca"));
        assertFalse(user1.equals(user2));
        assertEquals(user1.hashCode(), user2.hashCode());

        user2.getPrincipals().add(new X500Principal("cn=aaa,ou=ca"));
        assertEquals(user1, user1);
        assertEquals(user1.hashCode(), user2.hashCode());

        user1.posixDetails = new PosixDetails(12, 23,
                "/home/myhome");
        assertFalse(user1.equals(user2));
        assertEquals(user1.hashCode(), user2.hashCode());

        user2.getPrincipals().add(new X500Principal("cn=aaa,ou=ca"));
        assertEquals(user1, user1);
        assertEquals(user1.hashCode(), user2.hashCode());

        User<NumericPrincipal> user5 = new User<NumericPrincipal>(
                new NumericPrincipal(32));
        assertFalse(user1.equals(user5));
        
        // visual test of toString
        System.out.println(user1);
        System.out.println(user1.userDetails);
        System.out.println(user1.posixDetails);
        
    }
}
