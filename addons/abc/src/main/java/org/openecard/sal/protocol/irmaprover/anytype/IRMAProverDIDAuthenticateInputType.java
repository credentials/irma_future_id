/****************************************************************************
 * Copyright (C) 2014 Radboud University Nijmegen.
 * All rights reserved.
 *
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

/**
 * @author Antonio de la Piedra <a.delapiedra@cs.ru.nl>
 */
public class IRMAProverDIDAuthenticateInputType {

    private final AuthDataMap authMap;
    private String presentationPolicy;
    private String nonce;

    /**
     * Creates a new IRMAProverDIDAuthenticateInputType.
     *
     * @param data DIDAuthenticationDataType
     * @throws ParserConfigurationException
     */
    public IRMAProverDIDAuthenticateInputType(DIDAuthenticationDataType data) throws ParserConfigurationException {
	authMap = new AuthDataMap(data);
	// Optional contents
	presentationPolicy = authMap.getContentAsString("PresentationPolicy");
        nonce = authMap.getContentAsString("Nonce");
    }

    /**
     * Returns the PresentationPolicy.
     *
     * @return PresentationPolicy
     */
    public String getPresentationPolicy() {
	return presentationPolicy;
    }

    /**
     * Returns the Nonce.
     *
     * @return Nonce
     */
    public String getNonce() {
	return nonce;
    }

    /**
     * Returns a new IRMAProverDIDAuthenticateOutputType.
     *
     * @return IRMAProverDIDAuthenticateOutputType
     */
    public IRMAProverDIDAuthenticateOutputType getOutputType() {
	return new IRMAProverDIDAuthenticateOutputType(authMap);
    }

}
