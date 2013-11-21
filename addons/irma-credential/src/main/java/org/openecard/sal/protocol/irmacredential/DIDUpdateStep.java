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

package org.openecard.sal.protocol.irmacredential;

import iso.std.iso_iec._24727.tech.schema.ConnectionHandleType;
import iso.std.iso_iec._24727.tech.schema.DIDAuthenticate;
import iso.std.iso_iec._24727.tech.schema.DIDAuthenticateResponse;
import iso.std.iso_iec._24727.tech.schema.DIDScopeType;
import iso.std.iso_iec._24727.tech.schema.DIDStructureType;
import iso.std.iso_iec._24727.tech.schema.DIDUpdate;
import iso.std.iso_iec._24727.tech.schema.DIDUpdateResponse;
import iso.std.iso_iec._24727.tech.schema.DifferentialIdentityServiceActionName;
import iso.std.iso_iec._24727.tech.schema.InputUnitType;
import iso.std.iso_iec._24727.tech.schema.PasswordAttributesType;
import iso.std.iso_iec._24727.tech.schema.PinInputType;
import iso.std.iso_iec._24727.tech.schema.Transmit;
import iso.std.iso_iec._24727.tech.schema.TransmitResponse;
import iso.std.iso_iec._24727.tech.schema.VerifyUser;
import iso.std.iso_iec._24727.tech.schema.VerifyUserResponse;
import java.math.BigInteger;
import java.util.Map;
import org.openecard.addon.sal.FunctionType;
import org.openecard.addon.sal.ProtocolStep;
import org.openecard.common.ECardException;
import org.openecard.common.WSHelper;
import org.openecard.common.apdu.common.CardResponseAPDU;
import org.openecard.common.interfaces.Dispatcher;
import org.openecard.common.sal.Assert;
import org.openecard.common.sal.anytype.IRMACREDENTIALMarkerType;
import org.openecard.common.sal.state.CardStateEntry;
import org.openecard.common.sal.util.SALUtils;
import org.openecard.common.util.PINUtils;
//import org.openecard.sal.protocol.irmacredential.anytype.IRMACREDENTIALDIDUpdateDataType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Implements the DIDUpdate step of the PIN Compare protocol.
 * See TR-03112, version 1.1.2, part 7, section 4.1.3.
 *
 * @author Moritz Horsch <horsch@cdc.informatik.tu-darmstadt.de>
 */
public class DIDUpdateStep implements ProtocolStep<DIDUpdate, DIDUpdateResponse> {

    private static final Logger logger = LoggerFactory.getLogger(DIDUpdateStep.class);

    private final Dispatcher dispatcher;

    /**
     * Creates a new DIDAuthenticateStep.
     *
     * @param dispatcher Dispatcher
     */
    public DIDUpdateStep(Dispatcher dispatcher) {
	this.dispatcher = dispatcher;
    }

    @Override
    public FunctionType getFunctionType() {
	return FunctionType.DIDUpdate;
    }

    @Override
    public DIDUpdateResponse perform(DIDUpdate request, Map<String, Object> internalData) {
	DIDUpdateResponse response = WSHelper.makeResponse(DIDUpdateResponse.class, WSHelper.makeResultOK());
	/*
	try {/*
	    ConnectionHandleType connectionHandle = SALUtils.getConnectionHandle(request);
	    String didName = SALUtils.getDIDName(request);
	    CardStateEntry cardStateEntry = SALUtils.getCardStateEntry(internalData, connectionHandle);

	    byte[] cardApplication = connectionHandle.getCardApplication();
	    	    
	    IRMACREDENTIALDIDUpdateDataType pinCompare = new IRMACREDENTIALDIDUpdateDataType(request.getDIDUpdateData());

	    DIDStructureType didStructure = cardStateEntry.getDIDStructure(didName, cardApplication);
	    IRMACREDENTIALMarkerType pinCompareMarker = new IRMACREDENTIALMarkerType(didStructure.getDIDMarker());
	    byte[] slotHandle = connectionHandle.getSlotHandle();
	    PasswordAttributesType attributes = pinCompareMarker.getPasswordAttributes();
	    
	    String rawPIN    = pinCompare.getPIN();
	    String rawOldPIN = pinCompare.getOldPIN();
	    String rawAdminPIN = pinCompare.getAdminPIN();
	    
	    System.out.println("[*] DIDUpdateStep, new PIN: " + rawPIN);
	    System.out.println("[*] DIDUpdateStep, old PIN: " + rawOldPIN);
	    System.out.println("[*] DIDUpdateStep, adminPIN: " + rawAdminPIN);
	    
	    if (didName.equals("PIN.ATTRIBUTE")) {
	    
	        byte[] template_verify = new byte[] { 0x00, 0x20, 0x00, 0x01 };
	        byte[] responseCode_verify;

	        // we first send the admin (card) pin

	        Transmit verifyTransmit = PINUtils.buildVerifyTransmit(rawAdminPIN, attributes, template_verify, slotHandle);
	        TransmitResponse transResp = (TransmitResponse) dispatcher.deliver(verifyTransmit);
	        WSHelper.checkResult(transResp);
	        responseCode_verify = transResp.getOutputAPDU().get(0);
	    
	        CardResponseAPDU verifyReferenceResponseAPDU = new CardResponseAPDU(responseCode_verify);

	        cardStateEntry.addAuthenticated(didName, cardApplication);

	        // then we update the attribute (credential) pin

	        byte[] template_change = new byte[] { 0x00, 0x24, 0x00, 0x00 };
	        byte[] responseCode_change;

	        Transmit changeTransmit = PINUtils.buildVerifyTransmit(rawPIN, attributes, template_change, slotHandle);
	        TransmitResponse changeResp = (TransmitResponse) dispatcher.deliver(changeTransmit);
	        WSHelper.checkResult(changeResp);
	        responseCode_change = changeResp.getOutputAPDU().get(0);
	    
	        CardResponseAPDU changeReferenceResponseAPDU = new CardResponseAPDU(responseCode_change);

	        cardStateEntry.addAuthenticated(didName, cardApplication);
  
            } else if (didName.equals("PIN.ADMIN")) {

	        byte[] template_change_admin = new byte[] { 0x00, 0x24, 0x00, 0x01 };
	        byte[] responseCode_change_admin;

	        Transmit changeAdminTransmit = PINUtils.buildChangeReferenceTransmit(rawPIN, rawOldPIN, rawAdminPIN, attributes, template_change_admin, slotHandle);
	        TransmitResponse changeAdminResp = (TransmitResponse) dispatcher.deliver(changeAdminTransmit);
	        WSHelper.checkResult(changeAdminResp);
	        responseCode_change_admin = changeAdminResp.getOutputAPDU().get(0);
	    
	        CardResponseAPDU changeAdminReferenceResponseAPDU = new CardResponseAPDU(responseCode_change_admin);

	        cardStateEntry.addAuthenticated(didName, cardApplication);
            
            } else {
                // XXXX: TODO
            }              
	} catch (ECardException e) {
	    logger.error(e.getMessage(), e);
	    response.setResult(e.getResult());
	} catch (Exception e) {
	    logger.error(e.getMessage(), e);
	    response.setResult(WSHelper.makeResult(e));
	}
*/
	return response;

    }
}
