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

package org.openecard.sal.protocol.irmalog;

import iso.std.iso_iec._24727.tech.schema.ConnectionHandleType;
import iso.std.iso_iec._24727.tech.schema.DIDAuthenticate;
import iso.std.iso_iec._24727.tech.schema.DIDAuthenticateResponse;
import iso.std.iso_iec._24727.tech.schema.DIDAuthenticationDataType;
import iso.std.iso_iec._24727.tech.schema.DIDScopeType;
import iso.std.iso_iec._24727.tech.schema.DIDStructureType;
import iso.std.iso_iec._24727.tech.schema.DifferentialIdentityServiceActionName;
import iso.std.iso_iec._24727.tech.schema.InputUnitType;
import iso.std.iso_iec._24727.tech.schema.PasswordAttributesType;
import iso.std.iso_iec._24727.tech.schema.PinInputType;
import iso.std.iso_iec._24727.tech.schema.Transmit;
import iso.std.iso_iec._24727.tech.schema.TransmitResponse;
import iso.std.iso_iec._24727.tech.schema.VerifyUser;
import iso.std.iso_iec._24727.tech.schema.VerifyUserResponse;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Map;
import java.util.Vector;
import org.openecard.addon.sal.FunctionType;
import org.openecard.addon.sal.ProtocolStep;
import org.openecard.common.ECardException;
import org.openecard.common.WSHelper;
import org.openecard.common.apdu.common.CardResponseAPDU;
import org.openecard.common.interfaces.Dispatcher;
import org.openecard.common.sal.Assert;
import org.openecard.common.sal.anytype.IRMALOGMarkerType;
import org.openecard.common.sal.state.CardStateEntry;
import org.openecard.common.sal.util.SALUtils;
import org.openecard.common.util.PINUtils;
import org.openecard.common.util.IRMAUtils;
import org.openecard.sal.protocol.irmalog.anytype.IRMALOGDIDAuthenticateInputType;
import org.openecard.sal.protocol.irmalog.anytype.IRMALOGDIDAuthenticateOutputType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//import org.irmacard.idemix.util.IdemixLogEntry;

/**
 * Implements the DIDAuthenticate step of the PIN Compare protocol.
 * See TR-03112, version 1.1.2, part 7, section 4.1.5.
 *
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 * @author Moritz Horsch <horsch@cdc.informatik.tu-darmstadt.de>
 */
public class DIDAuthenticateStep implements ProtocolStep<DIDAuthenticate, DIDAuthenticateResponse> {

    private static final Logger logger = LoggerFactory.getLogger(DIDAuthenticateStep.class);
    private final Dispatcher dispatcher;

    /**
     * Creates a new DIDAuthenticateStep.
     *
     * @param dispatcher Dispatcher
     */
    public DIDAuthenticateStep(Dispatcher dispatcher) {
	this.dispatcher = dispatcher;
    }

    @Override
    public FunctionType getFunctionType() {
	return FunctionType.DIDAuthenticate;
    }

    @Override
    public DIDAuthenticateResponse perform(DIDAuthenticate request, Map<String, Object> internalData) {
	DIDAuthenticateResponse response = WSHelper.makeResponse(DIDAuthenticateResponse.class, WSHelper.makeResultOK());
        Vector<byte[]> list = new Vector<byte[]>();

	try {
	    ConnectionHandleType connectionHandle = SALUtils.getConnectionHandle(request);
	    String didName = SALUtils.getDIDName(request);
	    CardStateEntry cardStateEntry = SALUtils.getCardStateEntry(internalData, connectionHandle);
	    IRMALOGDIDAuthenticateInputType pinCompareInput = new IRMALOGDIDAuthenticateInputType(request.getAuthenticationProtocolData());
	    IRMALOGDIDAuthenticateOutputType pinCompareOutput = pinCompareInput.getOutputType();

	    byte[] cardApplication;
	    if (request.getDIDScope() != null && request.getDIDScope().equals(DIDScopeType.GLOBAL)) {
		cardApplication = cardStateEntry.getImplicitlySelectedApplicationIdentifier();
	    } else {
		cardApplication = connectionHandle.getCardApplication();
	    }
	    Assert.securityConditionDID(cardStateEntry, cardApplication, didName, DifferentialIdentityServiceActionName.DID_AUTHENTICATE);

	    DIDStructureType didStructure = cardStateEntry.getDIDStructure(didName, cardApplication);
	    IRMALOGMarkerType pinCompareMarker = new IRMALOGMarkerType(didStructure.getDIDMarker());
	    byte keyRef = pinCompareMarker.getPINRef().getKeyRef()[0];
	    byte[] slotHandle = connectionHandle.getSlotHandle();
	    PasswordAttributesType attributes = pinCompareMarker.getPasswordAttributes();
	    String rawPIN = pinCompareInput.getPIN();
	    byte[] template = new byte[] { 0x00, 0x20, 0x00, 0x01 };
	    byte[] responseCode;

	    // [TR-03112-6] The structure of the template corresponds to the
	    // structure of an APDU for the VERIFY command in accordance
	    // with [ISO7816-4] (Section 7.5.6).
	    if (rawPIN == null || rawPIN.isEmpty()) {
		VerifyUser verify = new VerifyUser();
		verify.setSlotHandle(slotHandle);

		InputUnitType inputUnit = new InputUnitType();
		verify.setInputUnit(inputUnit);

		PinInputType pinInput = new PinInputType();
		inputUnit.setPinInput(pinInput);
		pinInput.setIndex(BigInteger.ZERO);
		pinInput.setPasswordAttributes(attributes);

		verify.setTemplate(template);
		VerifyUserResponse verifyR = (VerifyUserResponse) dispatcher.deliver(verify);
		WSHelper.checkResult(verifyR);
		responseCode = verifyR.getResponse();
	    } else {
		Transmit verifyTransmit = PINUtils.buildVerifyTransmit(rawPIN, attributes, template, slotHandle);
		TransmitResponse transResp = (TransmitResponse) dispatcher.deliver(verifyTransmit);
		WSHelper.checkResult(transResp);
		responseCode = transResp.getOutputAPDU().get(0);
		
		// getLOG

                byte[] template_get_log = new byte[] { (byte) 0x80, (byte) 0x3B };
                byte[] responseCode_get_log;

                /* Taken from IdemixService.java, Pim Vullers, Radboud University Nijmegen, Copyright 2011 */
                
                int LOG_SIZE = 30;
                int LOG_ENTRY_SIZE = 16;
                byte LOG_ENTRIES_PER_APDU = 255 / 16;
                
                
                for (byte start_entry = 0; start_entry < LOG_SIZE;
                     start_entry = (byte) (start_entry + LOG_ENTRIES_PER_APDU)) {
                                                                                                  
                         Transmit getLogTransmit = IRMAUtils.buildGetLog(template_get_log, (byte) start_entry, (byte) 0x00, slotHandle);
                         TransmitResponse transRespGetLog = (TransmitResponse) dispatcher.deliver(getLogTransmit);
                         byte[] data = transRespGetLog.getOutputAPDU().get(0);
                         
                         
                         for (int entry = 0; entry < LOG_ENTRIES_PER_APDU
                             && entry + start_entry < LOG_SIZE; entry++) {
                                                                     
                                 byte[] log_entry = Arrays.copyOfRange(data, LOG_ENTRY_SIZE
                                                                       * entry, LOG_ENTRY_SIZE * (entry + 1));
                                                                                                             
                                 list.add(log_entry);
                         }                                                                                                                            
                         
                }
	    }

            pinCompareOutput.setLogList(list);
            response.setAuthenticationProtocolData(pinCompareOutput.getAuthDataType());	
	
	} catch (ECardException e) {
	    logger.error(e.getMessage(), e);
	    response.setResult(e.getResult());
	} catch (Exception e) {
	    logger.error(e.getMessage(), e);
	    response.setResult(WSHelper.makeResult(e));
	}

	return response;
    }

}
