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

import org.apache.log4j.Logger;
import org.junit.Test;
import static org.junit.Assert.*;

import ca.nrc.cadc.auth.HttpPrincipal;

public class GroupTest
{
    private static Logger log = Logger.getLogger(GroupTest.class);
    
    @Test
    public void simpleGroupTest() throws Exception
    {
        
        User<HttpPrincipal> owner = new User<HttpPrincipal>(new HttpPrincipal("owner"));
        Group group1 = new Group("TestGroup", owner);
        User<HttpPrincipal> user = new User<HttpPrincipal>(new HttpPrincipal("user"));
        
        group1.getUserMembers().add(user);
        assertEquals(1, group1.getUserMembers().size());

        Group group2 = group1;
        assertEquals(group1.hashCode(), group2.hashCode());
        assertEquals(group1, group2);
        assertTrue(group1 == group2);
        
        group2 = new Group("TestGroup", owner);
        assertEquals(group1.hashCode(), group2.hashCode());
        assertFalse(group1.equals(group2));
        
        group2.getUserMembers().add(user);
        assertEquals(group1.hashCode(), group2.hashCode());
        assertEquals(group1, group2);
        
        group1.getGroupMembers().add(group2);
        assertEquals(group1.hashCode(), group2.hashCode());
        assertFalse(group1.equals(group2));
        
        group2.getGroupMembers().add(group2);
        assertEquals(group1.hashCode(), group2.hashCode());
        assertEquals(group1, group2);
        
        group1.description = "Test group";
        assertEquals(group1.hashCode(), group2.hashCode());
        assertFalse(group1.equals(group2));
        
        group2.description = "Test group";
        assertEquals(group1.hashCode(), group2.hashCode());
        assertEquals(group1, group2);
        
        // group read and write equality tests     
        group1.groupRead = group2;
        assertEquals(group1.hashCode(), group2.hashCode());
        assertFalse(group1.equals(group2));
        
        group2.groupRead = group2;
        assertEquals(group1.hashCode(), group2.hashCode());
        assertEquals(group1, group2);
        
        // group write equality tests
        group1.groupWrite = group2;
        assertEquals(group1.hashCode(), group2.hashCode());
        assertFalse(group1.equals(group2));
        
        group2.groupWrite = group2;
        assertEquals(group1.hashCode(), group2.hashCode());
        assertEquals(group1, group2);
        
        group1.publicRead = true;
        assertEquals(group1.hashCode(), group2.hashCode());
        assertFalse(group1.equals(group2));
        
        group2.publicRead = true;
        assertEquals(group1.hashCode(), group2.hashCode());
        assertEquals(group1, group2);
        
        group2 = new Group("NewTestGroup", owner);
        assertFalse(group1.hashCode() == group2.hashCode());
        assertFalse(group1.equals(group2));
        
        // test toString
        System.out.println(group1);
    }
}
