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
import org.openecard.common.util.ByteUtils;


/**
 *
 * @author Tobias Wich <tobias.wich@ecsec.de>
 */
public class ApplicationTemplate extends TLVList {

    private byte[] applicationIdentifier;
    private byte[] applicationLabel;
    private byte[] fileReference;
    private byte[] commandAPDU;
    private byte[] discretionaryData;
    private CIODDO cioddo;
    private byte[] url;
    private TLVList appDataObjects;

    public ApplicationTemplate(TLV tlv) throws TLVException {
	super(tlv, 0x61);

	Parser p = new Parser(tlv.getChild());
	// application identifier
	if (p.match(0x4F)) {
	    applicationIdentifier = p.next(0).getValue();
	} else {
	    throw new TLVException("No ApplicationIdentifier defined in ApplicationTemplate.");
	}
	// application label
	applicationLabel = null;
	if (p.match(0x50)) {
	    applicationLabel = p.next(0).getValue();
	}
	// file reference
	fileReference = null;
	if (p.match(0x51)) {
	    fileReference = p.next(0).getValue();
	}
	// command apdu
	commandAPDU = null;
	if (p.match(0x52)) {
	    commandAPDU = p.next(0).getValue();
	}
	// discretionary data
	discretionaryData = null;
	if (p.match(0x53)) {
	    discretionaryData = p.next(0).getValue();
	}
	// cioddo
	cioddo = null;
	if (p.match(0x73)) {
	    if (discretionaryData != null) {
		throw new TLVException("DiscretionaryData already defined. CIODDO is forbidden then.");
	    }
	    cioddo = new CIODDO(p.next(0));
	}
	// url
	url = null;
	if (p.match(0x5F50)) {
	    url = p.next(0).getValue();
	}
	// set of application dataobjects
	appDataObjects = null;
	if (p.match(0x61)) {
	    appDataObjects = new TLVList(p.next(0));
	}
    }

    public ApplicationTemplate(byte[] data) throws TLVException {
	this(TLV.fromBER(data));
    }


    public byte[] getApplicationIdentifier() {
	return applicationIdentifier;
    }

    public boolean hasApplicationLabel() {
	return applicationLabel != null;
    }
    public byte[] getApplicationLabel() {
	return applicationLabel;
    }

    public boolean hasFileReference() {
	return fileReference != null;
    }
    public byte[] getFileReference() {
	return fileReference;
    }

    public boolean hasCommandAPDU() {
	return commandAPDU != null;
    }
    public byte[] getCommandAPDU() {
	return commandAPDU;
    }

    public boolean hasDiscretionaryData() {
	return discretionaryData != null;
    }
    public byte[] getDiscretionaryData() {
	return discretionaryData;
    }

    public boolean hasCIODDO() {
	return cioddo != null;
    }
    public CIODDO getCIODDO() {
	return cioddo;
    }

    public boolean hasURL() {
	return url != null;
    }
    public byte[] getURL() {
	return url;
    }

    public boolean hasApplicationDataObject() {
	return appDataObjects != null;
    }
    public TLVList getApplicationDataObjects() {
	return appDataObjects;
    }


    // useful definitions

    public boolean isCiaAid() {
	String aid = ByteUtils.toHexString(applicationIdentifier);
	aid = aid.toUpperCase();
	if (aid.startsWith("E828BD080F")) {
	    // TODO: more to check, but ok for now
	    return true;
	} else if (aid.equals("A000000063504B43532D3135")) {
	    // historical cia aid
	    return true;
	}

	return false;
    }

}
