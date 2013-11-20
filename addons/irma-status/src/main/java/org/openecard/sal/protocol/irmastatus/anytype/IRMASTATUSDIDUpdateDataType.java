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

package org.openecard.sal.protocol.irmastatus.anytype;

import iso.std.iso_iec._24727.tech.schema.DIDUpdateDataType;
import javax.xml.parsers.ParserConfigurationException;
import org.openecard.common.anytype.UpdateDataMap;

/**
 * Implements the PINCompareDIDUpdate.
 * See TR-03112, version 1.1.2, part 7, section 4.1.5.
 *
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 */
public class IRMASTATUSDIDUpdateDataType {

    private final UpdateDataMap updateMap;

    private String pin;
    private String oldPin;
    private String adminPin;

    /**
     * Creates a new PINCompareDIDUpdate.
     *
     * @param data DIDUpdateenticationDataType
     * @throws ParserConfigurationException
     */
    public IRMASTATUSDIDUpdateDataType(DIDUpdateDataType data) throws ParserConfigurationException {
	updateMap = new UpdateDataMap(data);
	// Optional contents
	pin = updateMap.getContentAsString("Pin");
	oldPin = updateMap.getContentAsString("OldPin");
	adminPin = updateMap.getContentAsString("AdminPin");
    }

    /**
     * Returns the new PIN.
     *
     * @return PIN
     */
    public String getPIN() {
	return pin;
    }

    /**
     * Returns the old PIN.
     *
     * @return PIN
     */
    public String getOldPIN() {
	return oldPin;
    }

    /**
     * Returns the Admin PIN.
     *
     * @return PIN
     */
    public String getAdminPIN() {
	return adminPin;
    }

}
