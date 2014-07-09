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

package org.openecard.common.sal.anytype;

import iso.std.iso_iec._24727.tech.schema.CardInfoType;
import iso.std.iso_iec._24727.tech.schema.DIDInfoType;
import java.math.BigInteger;
import org.openecard.common.ECardConstants;
import org.openecard.common.sal.anytype.ABC4TrustProverMarkerType;
import org.openecard.common.sal.state.cif.CardInfoWrapper;
import org.openecard.common.util.StringUtils;
import org.openecard.recognition.CardRecognition;
import org.testng.annotations.Test;
import static org.testng.Assert.*;


/**
 *
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 */
public class ABC4TrustProverMarkerTypeTest {

    private static final byte[] rootApplication = StringUtils.toByteArray("F84142433474727573");
    private static final String cardType = "https://www.abc4trust.org/abc4trust";
    private static final String didName = "ABC4Trust.PROVER";

    /**
     * Simple test for PinCompareMarkerType. After getting the PinCompareMarker for the PIN.home DID in the the root
     * application we check if the get-methods return the expected values.
     *
     * @throws Exception when something in this test went unexpectedly wrong
     */
    @Test
    public void testPinCompareMarkerType() throws Exception {
	CardRecognition recognition = new CardRecognition(null, null);
	CardInfoType cardInfo = recognition.getCardInfo(cardType);
	CardInfoWrapper cardInfoWrapper = new CardInfoWrapper(cardInfo);

	DIDInfoType didInfoWrapper = cardInfoWrapper.getDIDInfo(didName, rootApplication);

	ABC4TrustProverMarkerType marker = new ABC4TrustProverMarkerType(
		 didInfoWrapper.getDifferentialIdentity().getDIDMarker().getABC4TrustProverMarker());

	assertEquals(marker.getPolicy(), "default");
	assertEquals(marker.getProtocol(), ECardConstants.Protocol.ABC4Trust_PROVER);
    
    }
}
