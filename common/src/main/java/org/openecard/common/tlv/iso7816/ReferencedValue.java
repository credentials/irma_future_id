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


/**
 *
 * @author Tobias Wich <tobias.wich@ecsec.de>
 */
public class ReferencedValue extends TLVType {

    private Path path;
    private TLV url;

    public ReferencedValue(TLV tlv) throws TLVException {
	super(tlv);

	Parser p = new Parser(tlv);

	if (p.match(Tag.SEQUENCE_TAG)) {
	    path = new Path(p.next(0));
	} else if(p.match(new Tag(TagClass.UNIVERSAL, true, 19)) ||
		  p.match(new Tag(TagClass.UNIVERSAL, true, 22)) ||
		  p.match(new Tag(TagClass.CONTEXT, false, 3))) {
	    url = p.next(0); // TODO: create URL type
	} else {
	    throw new TLVException("Unexpected element in ObjectValue.");
	}
    }

}
