/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2026
 *  Government of Canada                 Gouvernement du Canada
 *  National Research Council            Conseil national de recherches
 *
 *  OpenCADC is free software:           OpenCADC est un logiciel libre ;
 *  you can redistribute it and/or       vous pouvez le redistribuer ou le
 *  modify it under the terms of         modifier suivant les termes de
 *  the GNU Affero General Public        la “GNU Affero General Public
 *  License as published by the          License” telle que publiée
 *  Free Software Foundation,            par la Free Software Foundation
 *  either version 3 of the              : soit la version 3 de cette
 *  License, or (at your option)        licence, soit (à votre gré)
 *  any later version.                  toute version ultérieure.
 *
 ************************************************************************
 */

package org.opencadc.permissions.client.srcnet;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * Result of {@code /v1/authorise/plugin} and {@code /v1/authorise/route}.
 */
public final class AuthorisationResult {

    public final boolean isAuthorised;

    private AuthorisationResult(boolean isAuthorised) {
        this.isAuthorised = isAuthorised;
    }

    static AuthorisationResult parse(final JSONObject jsonObject) throws JSONException {
        return new AuthorisationResult(jsonObject.getBoolean("is_authorised"));
    }
}
