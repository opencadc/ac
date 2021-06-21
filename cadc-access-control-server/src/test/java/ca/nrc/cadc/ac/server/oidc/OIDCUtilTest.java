/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2016.                            (c) 2016.
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
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */

package ca.nrc.cadc.ac.server.oidc;

import org.junit.Assert;
import org.junit.Test;

import ca.nrc.cadc.util.Log4jInit;
import ca.nrc.cadc.util.PropertiesReader;


public class OIDCUtilTest
{

    static
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", org.apache.log4j.Level.INFO);
    }
    
    @Test
    public void testNoSuchProperties() throws Exception {
        System.setProperty(PropertiesReader.class.getName() + ".dir", "src/test/config");
        System.setProperty("user.home", "src/test/config");

        String oidc = "clientID";
        String secret = "clientSecret";
        RelyParty actual = OIDCUtil.getRelyParty(oidc);
        Assert.assertEquals("Incorrect client ID", oidc, actual.getClientID());
        Assert.assertEquals("Incorrect client secret", secret, actual.getClientSecret());
        
    }
}
