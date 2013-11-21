/****************************************************************************
 * Copyright (C) 2012 HS Coburg.
 * All rights reserved.
 * Contact: ecsec GmbH (info@ecsec.de)
 *
 * This file is part of the Open eCard App.
 *
 * GNU General Public License Usage
 * This file may be used under the terms of the GNU General Public
 * License version 3.0 as published by the Free Software Foundation
 * and appearing in the file LICENSE.GPL included in the packaging of
 * this file. Please review the following information to ensure the
 * GNU General Public License version 3.0 requirements will be met:
 * http://www.gnu.org/copyleft/gpl.html.
 *
 * Other Usage
 * Alternatively, this file may be used in accordance with the terms
 * and conditions contained in a signed written agreement between
 * you and ecsec GmbH.
 *
 ***************************************************************************/

package org.openecard.sal.protocol.irmacredential.anytype;

import iso.std.iso_iec._24727.tech.schema.DIDAuthenticationDataType;
import java.math.BigInteger;
import javax.xml.parsers.ParserConfigurationException;
import org.openecard.common.anytype.AuthDataMap;
import org.openecard.common.anytype.AuthDataResponse;
import java.util.Vector;

/**
 * Implements the PINCompareDIDAuthenticateOutputType.
 * See TR-03112, version 1.1.2, part 7, section 4.1.5.
 *
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 */
public class IRMACREDENTIALDIDAuthenticateOutputType {

    private final AuthDataMap authMap;
    Vector<Integer> list;
    

    /**
     * Creates a new PINCompareDIDAuthenticateOutputType.
     *
     * @param data DIDAuthenticationDataType
     * @throws ParserConfigurationException
     */
    public IRMACREDENTIALDIDAuthenticateOutputType(DIDAuthenticationDataType data) throws ParserConfigurationException {
        list = new Vector<Integer>();
	authMap = new AuthDataMap(data);
    }

    /**
     * Creates a new PINCompareDIDAuthenticateOutputType.
     *
     * @param authMap AuthDataMap
     */
    protected IRMACREDENTIALDIDAuthenticateOutputType(AuthDataMap authMap) {
	this.authMap = authMap;
    }

    /**
     * Returns the retry counter.
     *
     * @return Retry counter
     */
    public Vector<Integer> getCredList() {
	return list;
    }

    /**
     * Sets the retry counter.
     *
     * @param logEntry Retry counter
     */
    public void setCredList(Vector<Integer> list) {
	this.list = list;	
    }

    /**
     *
     * @return the PinCompareDIDAuthenticateOutputType
     */
    public DIDAuthenticationDataType getAuthDataType() {

	iso.std.iso_iec._24727.tech.schema.PinCompareDIDAuthenticateOutputType pinCompareOutput;
	pinCompareOutput = new iso.std.iso_iec._24727.tech.schema.PinCompareDIDAuthenticateOutputType();
	AuthDataResponse authResponse = authMap.createResponse(pinCompareOutput);
	
	for (Integer cred: list) {
            authResponse.addElement("CredEntry", String.valueOf(cred));
        }
	    
	return authResponse.getResponse();
    }
}
