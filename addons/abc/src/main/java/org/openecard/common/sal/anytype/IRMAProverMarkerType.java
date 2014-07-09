/****************************************************************************
 * Copyright (C) 2014 Radboud University Nijmegen.
 * All rights reserved.
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
 ***************************************************************************/

package org.openecard.common.sal.anytype;

import iso.std.iso_iec._24727.tech.schema.KeyRefType;
import iso.std.iso_iec._24727.tech.schema.PasswordAttributesType;
import iso.std.iso_iec._24727.tech.schema.PasswordTypeType;
import iso.std.iso_iec._24727.tech.schema.StateInfoType;
import java.math.BigInteger;
import java.util.Arrays;
import org.openecard.common.util.StringUtils;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;


/**
 *
 * @author Antonio de la Piedra <a.delapiedra@cs.ru.nl>
 */
public class IRMAProverMarkerType {

    private String policy = null;
    private String protocol;

    public IRMAProverMarkerType(iso.std.iso_iec._24727.tech.schema.DIDAbstractMarkerType didAbstractMarkerType) {
	if(!(didAbstractMarkerType instanceof iso.std.iso_iec._24727.tech.schema.IRMAProverMarkerType)){
	    throw new IllegalArgumentException();
	}

	protocol = didAbstractMarkerType.getProtocol();

	for (Element e : didAbstractMarkerType.getAny()) 
	    if (e.getLocalName().equals("Policy")) 
		policy = e.getTextContent();
    }

    public String getPolicy() {
	return policy;
    }

    public String getProtocol() {
	return protocol;
    }

    public StateInfoType getStateInfo() {
	throw new UnsupportedOperationException("Not yet implemented");
    }
}
