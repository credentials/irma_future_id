/****************************************************************************
 * Copyright (C) 2012 ecsec GmbH.
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

package org.openecard.common.tlv.iso7816;

import org.openecard.common.tlv.Parser;
import org.openecard.common.tlv.TLV;
import org.openecard.common.tlv.TLVException;
import org.openecard.common.tlv.Tag;
import org.openecard.common.tlv.TagClass;
import org.openecard.common.util.ByteUtils;


/**
 *
 * @author Tobias Wich <tobias.wich@ecsec.de>
 */
public class PasswordAttributes extends TLVType {

    private TLVBitString passwordFlags;
    private int passwordType; // enum PasswordType
    private int minLength;
    private int storedLength;
    private Integer maxLength;
    private Integer passwordReference;
    private Byte padChar;
    private TLV lastPasswordChange;
    private Path path;


    public PasswordAttributes(TLV tlv) throws TLVException {
	super(tlv);

	Parser p = new Parser(tlv.getChild());

	if (p.match(Tag.BITSTRING_TAG)) {
	    passwordFlags = new TLVBitString(p.next(0));
	} else {
	    throw new TLVException("passwordFlags element missing.");
	}
	if (p.match(Tag.ENUMERATED_TAG)) {
	    passwordType = ByteUtils.toInteger(p.next(0).getValue());
	} else {
	    throw new TLVException("passwordType element missing.");
	}
	if (p.match(Tag.INTEGER_TAG)) {
	    minLength = ByteUtils.toInteger(p.next(0).getValue());
	} else {
	    throw new TLVException("minLength element missing.");
	}
	if (p.match(Tag.INTEGER_TAG)) {
	    storedLength = ByteUtils.toInteger(p.next(0).getValue());
	} else {
	    throw new TLVException("storedLength element missing.");
	}
	if (p.match(Tag.INTEGER_TAG)) {
	    maxLength = ByteUtils.toInteger(p.next(0).getValue());
	}
	if (p.match(new Tag(TagClass.CONTEXT, true, 0))) {
	    passwordReference = ByteUtils.toInteger(p.next(0).getValue());
	}
	if (p.match(Tag.OCTETSTRING_TAG)) {
	    padChar = p.next(0).getValue()[0];
	}
	if (p.match(new Tag(TagClass.UNIVERSAL, true, 24))) {
	    lastPasswordChange = p.next(0);
	}
	if (p.match(Tag.SEQUENCE_TAG)) {
	    path = new Path(p.next(0));
	}
    }

}
