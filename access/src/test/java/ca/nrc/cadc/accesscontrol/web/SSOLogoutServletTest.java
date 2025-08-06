/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2012.                         (c) 2012.
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
 * 4/19/12 - 9:26 AM
 *
 *
 *
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */
package ca.nrc.cadc.accesscontrol.web;

import ca.nrc.cadc.accesscontrol.AbstractAccessControlWebTest;

import ca.nrc.cadc.auth.SSOCookieManager;

import ca.nrc.cadc.date.DateUtil;
import org.junit.Test;

import java.util.Arrays;
import java.util.Calendar;

import static org.junit.Assert.assertArrayEquals;


public class SSOLogoutServletTest extends AbstractAccessControlWebTest<SSOLogoutServlet> {
    @Test
    public void logout() {
        final char[] expected = "LOGOUT".toCharArray();
        final SSOCookieManager cookieManager = new SSOCookieManager() {
            /**
             * Testers can override this to provide a consistent test.
             *
             * @return Calendar instance.  Never null.
             */
            @Override
            public Calendar getCurrentCalendar() {
                final Calendar expiryCal = Calendar.getInstance(DateUtil.UTC);

                // Dustin's 60th birthday.
                expiryCal.set(2037, Calendar.NOVEMBER, 25, 3, 21, 0);
                expiryCal.set(Calendar.MILLISECOND, 0);

                return expiryCal;
            }
        };

        setTestSubject(new SSOLogoutServlet(cookieManager) {
            @Override
            char[] getLogoutCookieValue() {
                return expected;
            }
        });

        cookieManager.setOffsetExpiryHours(-1);

        final char[] result = getTestSubject().authorizeCookie("CADCtest", "password");

        assertArrayEquals("Generated cookie value is wrong.  Expecting \n"
                          + Arrays.toString(expected) + "\n and saw \n"
                          + Arrays.toString(result), expected, result);
    }
}
