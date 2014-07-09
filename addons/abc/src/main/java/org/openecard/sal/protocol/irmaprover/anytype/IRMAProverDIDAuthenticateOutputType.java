/****************************************************************************
 * Copyright (C) 2014 Radboud University Nijmegen
 * All rights reserved.

 * GNU General Public License Usage
 * This file may be used under the terms of the GNU General Public
 * License version 3.0 as published by the Free Software Foundation
 * and appearing in the file LICENSE.GPL included in the packaging of
 * this file. Please review the following information to ensure the
 * GNU General Public License version 3.0 requirements will be met:
 * http://www.gnu.org/copyleft/gpl.html.
 *
 ***************************************************************************/

package org.openecard.sal.protocol.irmaprover.anytype;

import iso.std.iso_iec._24727.tech.schema.DIDAuthenticationDataType;
import javax.xml.parsers.ParserConfigurationException;
import org.openecard.common.anytype.AuthDataMap;
import org.openecard.common.anytype.AuthDataResponse;


/**
 * Implements the IRMAProverDIDAuthenticateOutputType.
 *
 * @author Antonio de la Piedra <a.delapiedra@cs.ru.nl>
 */
public class IRMAProverDIDAuthenticateOutputType {

    private final AuthDataMap authMap;
    private String presentationToken;

    /**
     * Creates a new IRMAProverDIDAuthenticateOutputType.
     *
     * @param data DIDAuthenticationDataType
     * @throws ParserConfigurationException
     */
    public IRMAProverDIDAuthenticateOutputType(DIDAuthenticationDataType data) throws ParserConfigurationException {
	authMap = new AuthDataMap(data);
    }

    /**
     * Creates a new IRMAProverDIDAuthenticateOutputType.
     *
     * @param authMap AuthDataMap
     */
    protected IRMAProverDIDAuthenticateOutputType(AuthDataMap authMap) {
	this.authMap = authMap;
    }

    /**
     * Returns the retry counter.
     *
     * @return Retry counter
     */
    public String getPresentationToken() {
	return presentationToken;
    }

    /**
     * Sets the retry counter.
     *
     * @param presentationToken Retry counter
     */
    public void setPresentationToken(String presentationToken) {
	this.presentationToken = presentationToken;
    }

    /**
     *
     * @return the IRMAProverDIDAuthenticateOutputType
     */
    public DIDAuthenticationDataType getAuthDataType() {
	iso.std.iso_iec._24727.tech.schema.IRMAProverDIDAuthenticateOutputType irmaProverOutput;
	irmaProverOutput = new iso.std.iso_iec._24727.tech.schema.IRMAProverDIDAuthenticateOutputType();
	AuthDataResponse authResponse = authMap.createResponse(irmaProverOutput);
	if (presentationToken != null) {
	    authResponse.addElement("PresentationToken", presentationToken);
	}

	return authResponse.getResponse();
    }

}
