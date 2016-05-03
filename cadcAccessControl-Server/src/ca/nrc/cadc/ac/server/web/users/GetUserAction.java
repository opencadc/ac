/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2014.                            (c) 2014.
 *  Government of Canada                 Gouvernement du Canada
 *  National Research Council            Conseil national de recherches
 *  Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 *  All rights reserved                  Tous droits réservés
 *
 *  NRC disclaims any warranties,        Le CNRC dénie toute garantie
 *  expressed, implied, or               énoncée, implicite ou légale,
 *  statutory, of any kind with          de quelque nature que ce
 *  respect to the software,             soit, concernant le logiciel,
 *  including without limitation         y compris sans restriction
 *  any warranty of merchantability      toute garantie de valeur
 *  or fitness for a particular          marchande ou de pertinence
 *  purpose. NRC shall not be            pour un usage particulier.
 *  liable in any event for any          Le CNRC ne pourra en aucun cas
 *  damages, whether direct or           être tenu responsable de tout
 *  indirect, special or general,        dommage, direct ou indirect,
 *  consequential or incidental,         particulier ou général,
 *  arising from the use of the          accessoire ou fortuit, résultant
 *  software.  Neither the name          de l'utilisation du logiciel. Ni
 *  of the National Research             le nom du Conseil National de
 *  Council of Canada nor the            Recherches du Canada ni les noms
 *  names of its contributors may        de ses  participants ne peuvent
 *  be used to endorse or promote        être utilisés pour approuver ou
 *  products derived from this           promouvoir les produits dérivés
 *  software without specific prior      de ce logiciel sans autorisation
 *  written permission.                  préalable et particulière
 *                                       par écrit.
 *
 *  This file is part of the             Ce fichier fait partie du projet
 *  OpenCADC project.                    OpenCADC.
 *
 *  OpenCADC is free software:           OpenCADC est un logiciel libre ;
 *  you can redistribute it and/or       vous pouvez le redistribuer ou le
 *  modify it under the terms of         modifier suivant les termes de
 *  the GNU Affero General Public        la “GNU Affero General Public
 *  License as published by the          License” telle que publiée
 *  Free Software Foundation,            par la Free Software Foundation
 *  either version 3 of the              : soit la version 3 de cette
 *  License, or (at your option)         licence, soit (à votre gré)
 *  any later version.                   toute version ultérieure.
 *
 *  OpenCADC is distributed in the       OpenCADC est distribué
 *  hope that it will be useful,         dans l’espoir qu’il vous
 *  but WITHOUT ANY WARRANTY;            sera utile, mais SANS AUCUNE
 *  without even the implied             GARANTIE : sans même la garantie
 *  warranty of MERCHANTABILITY          implicite de COMMERCIALISABILITÉ
 *  or FITNESS FOR A PARTICULAR          ni d’ADÉQUATION À UN OBJECTIF
 *  PURPOSE.  See the GNU Affero         PARTICULIER. Consultez la Licence
 *  General Public License for           Générale Publique GNU Affero
 *  more details.                        pour plus de détails.
 *
 *  You should have received             Vous devriez avoir reçu une
 *  a copy of the GNU Affero             copie de la Licence Générale
 *  General Public License along         Publique GNU Affero avec
 *  with OpenCADC.  If not, see          OpenCADC ; si ce n’est
 *  <http://www.gnu.org/licenses/>.      pas le cas, consultez :
 *                                       <http://www.gnu.org/licenses/>.
 *
 *  $Revision: 4 $
 *
 ************************************************************************
 */package ca.nrc.cadc.ac.server.web.users;

import java.security.AccessController;
import java.security.Principal;

import javax.security.auth.Subject;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.profiler.Profiler;


public class GetUserAction extends AbstractUserAction
{
    private static final Logger log = Logger.getLogger(GetUserAction.class);

    private Profiler profiler = new Profiler(GetUserAction.class);

    private final Principal userID;
    private final String detail;

    GetUserAction(Principal userID, String detail)
    {
        super();
        this.userID = userID;
        this.detail = detail;
    }

	public void doAction() throws Exception
    {
        User user = getUser(this.userID);
        profiler.checkpoint("getUser");
        writeUser(user);
        profiler.checkpoint("writeUser");
    }

    protected User getUser(Principal principal) throws Exception
    {
        User user;

        /**
         * Special case 1
         * If the calling Subject user is the notAugmentedX500User, AND it is
         * a GET, call the userDAO to get the User with all identities.
         */
        if (isPrivilegedUser())
        {
            log.debug("getting augmented user " + principal.getName());
            user = userPersistence.getAugmentedUser(principal);
            profiler.checkpoint("getAugmentedUser");
        }

        /**
         * Special case 2
         * If detail=identity, AND if the calling Subject user is the same as
         * the requested User, then return the User with the principals from the
         * Subject which has already been augmented.
         */
        else if (detail != null &&
                 detail.equalsIgnoreCase("identity") &&
                 isSubjectUser(principal))
        {
            log.debug("augmenting " + principal.getName() + " from subject");
            Subject subject = Subject.getSubject(AccessController.getContext());
            user = new User();
            user.getIdentities().addAll(subject.getPrincipals());
            profiler.checkpoint("added identities");
        }
        else
        {
            log.debug("getting user " + principal.getName());
            try
            {
                user = userPersistence.getUser(principal);
                profiler.checkpoint("getUser");
            }
            catch (UserNotFoundException e)
            {
                user = userPersistence.getUserRequest(principal);
                profiler.checkpoint("getUserRequest");
            }

            // Only return user profile info, first and last name.
            if (detail != null && detail.equalsIgnoreCase("display"))
            {
                user.getIdentities().clear();
                user.posixDetails = null;
                if (user.personalDetails == null)
                {
                    String error = principal.getName() + " missing required PersonalDetails";
                    throw new IllegalStateException(error);
                }
                user.personalDetails = new PersonalDetails(user.personalDetails.getFirstName(), user.personalDetails.getLastName());
                profiler.checkpoint("addUserDetails");
            }
        }

    	return user;
    }

    protected boolean isSubjectUser(Principal userPrincipal)
    {
    	boolean isSubjectUser = false;
        Subject subject = Subject.getSubject(AccessController.getContext());
        if (subject != null)
        {
        	for (Principal subjectPrincipal : subject.getPrincipals())
        	{
        		if (subjectPrincipal.getName().equals(userPrincipal.getName()))
        		{
                    isSubjectUser = true;
        			break;
        		}
        	}
        }
        profiler.checkpoint("isSubjectUser");
        return isSubjectUser;
    }
}
