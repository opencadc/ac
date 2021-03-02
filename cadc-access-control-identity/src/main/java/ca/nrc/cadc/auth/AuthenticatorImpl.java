/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2017.                            (c) 2017.
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
*/

package ca.nrc.cadc.auth;

import java.net.URI;
import java.net.URL;
import java.security.AccessControlException;

import javax.security.auth.Subject;

import org.apache.log4j.Logger;

import ca.nrc.cadc.profiler.Profiler;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.vosi.avail.CheckResource;
import ca.nrc.cadc.vosi.avail.CheckWebService;

/**
 * Implementation of default Authenticator for AuthenticationUtil in cadcUtil.
 * This class augments the subject with additional identities using the access
 * control library.
 *
 * @author pdowler
 */
public class AuthenticatorImpl implements Authenticator
{

    private static final Logger log = Logger.getLogger(AuthenticatorImpl.class);

    public AuthenticatorImpl()
    {
    }
    


    /**
     * If necessary, validate principals in the subject.
     * 
     * @param subject The subject to be validated.
     * @return The validated subject with added public credentials.
     */
    @Override
    public Subject validate(Subject subject) throws AccessControlException {
        return AuthenticationUtil.validateTokens(subject);
    }

    /**
     * Augment the subject with the missing principals.
     * 
     * @param subject The subject to augment.
     * @return The augmented subject.
     */
    @Override
    public Subject augment(Subject subject) {
        AuthMethod am = AuthenticationUtil.getAuthMethod(subject);
        if (am == null || AuthMethod.ANON.equals(am))
        {
            return subject;
        }

        if (subject != null && subject.getPrincipals().size() > 0)
        {
            Profiler prof = new Profiler(AuthenticatorImpl.class);
            this.augmentSubject(subject);
            prof.checkpoint("AuthenticatorImpl.augmentSubject()");
        }

        return subject;
    }


    protected void augmentSubject(Subject subject)
    {
        ACIdentityManager identityManager = new ACIdentityManager();
        identityManager.augmentSubject(subject);
    }

    public static CheckResource getAvailabilityCheck()
    {
        RegistryClient regClient = new RegistryClient();
        LocalAuthority localAuth = new LocalAuthority();
        URI serviceURI = localAuth.getServiceURI(Standards.UMS_USERS_01.toASCIIString());
        URL availURL = regClient.getServiceURL(serviceURI, Standards.VOSI_AVAILABILITY, AuthMethod.ANON);
        return new CheckWebService(availURL.toExternalForm());
    }
    
}
