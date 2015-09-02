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

import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.server.UserPersistence;

import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedExceptionAction;
import java.util.Set;

import javax.security.auth.Subject;

import org.apache.log4j.Logger;


public class GetUserAction extends AbstractUserAction
{
    private static final Logger log = Logger.getLogger(GetUserAction.class);
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
        User<Principal> user;
 
        if (isServops())
        {
        	Subject subject = new Subject();
        	subject.getPrincipals().add(this.userID);
        	user = (User<Principal>) Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        	{
				@Override
				public Object run() throws Exception 
				{
					return getUser(userID);
				}
        		
        	});
        }
        else
        {
        	user = getUser(this.userID);
        }

        writeUser(user);
    }

    protected User<Principal> getUser(Principal principal) throws Exception
    {
        User<Principal> user;

        // For detail=identity, if the calling user is the same as the requested user,
        // the calling user already has all principals for that user.
        if (detail != null && detail.equalsIgnoreCase("identity") &&
            isSubjectUser(principal.getName()))
        {
            Subject subject = Subject.getSubject(AccessController.getContext());
            user = new User<Principal>(principal);
            user.getIdentities().addAll(subject.getPrincipals());
        }
        else
        {
            final UserPersistence<Principal> userPersistence = getUserPersistence();
            try
            {
                user = userPersistence.getUser(principal);
                if (detail != null)
                {
                    // Only return user principals
                    if (detail.equalsIgnoreCase("identity"))
                    {
                        user.details.clear();
                    }
                    // Only return user profile info, first and last name.
                    else if (detail.equalsIgnoreCase("display"))
                    {
                        user.getIdentities().clear();
                        Set<PersonalDetails> details = user.getDetails(PersonalDetails.class);
                        if (details.isEmpty())
                        {
                            String error = principal.getName() + " missing required PersonalDetails";
                            throw new IllegalStateException(error);
                        }
                        PersonalDetails pd = details.iterator().next();
                        user.details.clear();
                        user.details.add(new PersonalDetails(pd.getFirstName(), pd.getLastName()));
                    }
                    else
                    {
                        throw new IllegalArgumentException("Illegal detail parameter " + detail);
                    }
                }
            }
            catch (UserNotFoundException e)
            {
                user = userPersistence.getPendingUser(principal);
            }
        }
    	
    	return user;
    }
    
    protected boolean isServops()
    {
    	boolean isServops = false;
        AccessControlContext acc = AccessController.getContext();
        Subject subject = Subject.getSubject(acc);
        if (subject != null)
        {
        	for (Principal principal : subject.getPrincipals())
        	{
        		if (principal.getName().equals(this.getAugmentUserDN()))
        		{
        			isServops = true;
        			break;
        		}
        	}
        }

        return found;
    }
}
