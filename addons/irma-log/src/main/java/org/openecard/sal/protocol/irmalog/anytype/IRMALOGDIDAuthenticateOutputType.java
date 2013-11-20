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

package org.openecard.sal.protocol.irmalog.anytype;

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
public class IRMALOGDIDAuthenticateOutputType {

    private final AuthDataMap authMap;
    Vector<byte[]> list;
    

    /**
     * Creates a new PINCompareDIDAuthenticateOutputType.
     *
     * @param data DIDAuthenticationDataType
     * @throws ParserConfigurationException
     */
    public IRMALOGDIDAuthenticateOutputType(DIDAuthenticationDataType data) throws ParserConfigurationException {
        list = new Vector<byte[]>();
	authMap = new AuthDataMap(data);
    }

    /**
     * Creates a new PINCompareDIDAuthenticateOutputType.
     *
     * @param authMap AuthDataMap
     */
    protected IRMALOGDIDAuthenticateOutputType(AuthDataMap authMap) {
	this.authMap = authMap;
    }

    /**
     * Returns the retry counter.
     *
     * @return Retry counter
     */
    public Vector<byte[]> getLogList() {
	return list;
    }

    /**
     * Sets the retry counter.
     *
     * @param logEntry Retry counter
     */
    public void setLogList(Vector<byte[]> list) {
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
	
	for (byte[] byteArray: list) {
            authResponse.addElement("logEntry", bytesToHex(byteArray));
        }
	    
	return authResponse.getResponse();
    }

final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
public static String bytesToHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
        int v;
            for ( int j = 0; j < bytes.length; j++ ) {
                    v = bytes[j] & 0xFF;
                            hexChars[j * 2] = hexArray[v >>> 4];
                                    hexChars[j * 2 + 1] = hexArray[v & 0x0F];
                                        }
                                            return new String(hexChars);
                                            }



}
