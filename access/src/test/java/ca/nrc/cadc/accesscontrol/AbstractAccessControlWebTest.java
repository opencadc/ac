/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2010.                         (c) 2010.
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
 * @author jenkinsd
 * Oct 7, 2010 - 11:07:11 AM
 *
 *
 *
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */
package ca.nrc.cadc.accesscontrol;

import org.junit.After;
import org.junit.BeforeClass;
import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import ca.nrc.cadc.util.RsaSignatureGenerator;


public abstract class AbstractAccessControlWebTest<T>
{
    protected T testSubject;
    
    static {
        try {
            generateTestKeys();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate test keys", e);
        }
    }
    private static void generateTestKeys() throws Exception {
        File keyDir = new File("build/resources/test");
        if (!keyDir.exists() && !keyDir.mkdirs()) {
           throw new IllegalStateException("Could not create test resources dir: " + keyDir.getAbsolutePath());
        }
        File privKeyFile = new File(keyDir, "RsaSignaturePriv.key");
        File pubKeyFile  = new File(keyDir, "RsaSignaturePub.key");
        if (privKeyFile.exists() && pubKeyFile.exists()) {
            return;
        }
        RsaSignatureGenerator.genKeyPair(pubKeyFile, privKeyFile, 2048);
    }

    @After
    public void tearDown()
    {
        setTestSubject(null);
    }


    protected T getTestSubject()
    {
        return testSubject;
    }

    protected void setTestSubject(T testSubject)
    {
        this.testSubject = testSubject;
    }
}
