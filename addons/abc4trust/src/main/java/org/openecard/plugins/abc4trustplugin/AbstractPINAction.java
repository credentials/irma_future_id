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

package org.openecard.plugins.abc4trustplugin;

import iso.std.iso_iec._24727.tech.schema.CardApplicationConnect;
import iso.std.iso_iec._24727.tech.schema.CardApplicationConnectResponse;
import iso.std.iso_iec._24727.tech.schema.CardApplicationPath;
import iso.std.iso_iec._24727.tech.schema.CardApplicationPathResponse;
import iso.std.iso_iec._24727.tech.schema.ConnectionHandleType;
import iso.std.iso_iec._24727.tech.schema.GetIFDCapabilities;
import iso.std.iso_iec._24727.tech.schema.GetIFDCapabilitiesResponse;
import iso.std.iso_iec._24727.tech.schema.InputAPDUInfoType;
import iso.std.iso_iec._24727.tech.schema.SlotCapabilityType;
import iso.std.iso_iec._24727.tech.schema.Transmit;
import iso.std.iso_iec._24727.tech.schema.TransmitResponse;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Vector;
import java.util.Arrays;
import org.openecard.addon.bind.AppExtensionAction;
import org.openecard.common.I18n;
import org.openecard.common.WSHelper;
import org.openecard.common.WSHelper.WSException;
import org.openecard.common.ifd.PACECapabilities;
import org.openecard.common.interfaces.Dispatcher;
import org.openecard.common.interfaces.DispatcherException;
import org.openecard.common.sal.state.CardStateMap;
import org.openecard.common.util.ByteUtils;
import org.openecard.common.util.StringUtils;
import org.openecard.common.sal.util.InsertCardDialog;
import org.openecard.gui.UserConsent;
import org.openecard.recognition.CardRecognition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Common superclass for {@code ChangePINAction} and {@code UnblockPINAction}.
 * Bundles methods needed in both actions.
 * 
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 */
public abstract class AbstractPINAction implements AppExtensionAction {

    // translation and logger
    protected final I18n lang = I18n.getTranslation("pinplugin");
    private static final Logger logger = LoggerFactory.getLogger(AbstractPINAction.class);

    // constants
    protected static final String GERMAN_IDENTITY_CARD = "http://bsi.bund.de/cif/npa.xml";
    private static final byte[] recognizeCommandAPDU = StringUtils.toByteArray("0022C1A40F800A04007F00070202040202830103");

    private static final byte[] credVerifyAPDU = StringUtils.toByteArray("00200001083030303030300000"); //XXX: Cambiar luego
    private static final byte[] credListAPDU = StringUtils.toByteArray("803A0000"); 
    
    private static final byte[] RESPONSE_RC3 = new byte[] { (byte) 0x90, 0x00 };
    private static final byte[] RESPONSE_BLOCKED = new byte[] { (byte) 0x63, (byte) 0xC0 };
    private static final byte[] RESPONSE_SUSPENDED = new byte[] { (byte) 0x63, (byte) 0xC1 };
    private static final byte[] RESPONSE_RC2 = new byte[] { (byte) 0x63, (byte) 0xC2 };
    private static final byte[] RESPONSE_DEACTIVATED = new byte[] { (byte) 0x62, (byte) 0x83 };

    protected Dispatcher dispatcher;
    protected UserConsent gui;
    protected CardRecognition recognition;
    protected CardStateMap cardStates;

    /**
     * Recognize the PIN state of the card given through the connection handle.
     * 
     * @param cHandle
     *            The connection handle for the card for which the pin state should be recognized.
     * @return The recognized State (may be {@code RecognizedState.UNKNOWN}).
     * @throws InvocationTargetException In case the dispatched method throws an exception.
     * @throws DispatcherException In case a reflection error in the dispatcher occurs.
     */
    protected RecognizedState recognizeState(ConnectionHandleType cHandle) throws InvocationTargetException,
	    DispatcherException {

	Transmit t = new Transmit();
	t.setSlotHandle(cHandle.getSlotHandle());
	InputAPDUInfoType inputAPDU = new InputAPDUInfoType();
	inputAPDU.setInputAPDU(recognizeCommandAPDU);
	t.getInputAPDUInfo().add(inputAPDU);
	TransmitResponse response = (TransmitResponse) dispatcher.deliver(t);

	byte[] responseAPDU = response.getOutputAPDU().get(0);

	RecognizedState state;
	if (ByteUtils.compare(RESPONSE_RC3, responseAPDU)) {
	    state = RecognizedState.PIN_activated_RC3;
	} else if (ByteUtils.compare(RESPONSE_DEACTIVATED, responseAPDU)) {
	    state = RecognizedState.PIN_deactivated;
	} else if (ByteUtils.compare(RESPONSE_RC2, responseAPDU)) {
	    state = RecognizedState.PIN_activated_RC2;
	} else if (ByteUtils.compare(RESPONSE_SUSPENDED, responseAPDU)) {
	    state = RecognizedState.PIN_suspended;
	} else if (ByteUtils.compare(RESPONSE_BLOCKED, responseAPDU)) {
	    state = RecognizedState.PIN_blocked;
	} else {
	    logger.error("Unhandled response to the PIN state recognition APDU: {}\n");
	    state = RecognizedState.UNKNOWN;
	}

	logger.info("State of the PIN: {}.", state);
	return state;
    }

    /**
     * Retrieve a list of credentials from the IRMA card
     * 
     * @param cHandle
     *            The connection handle for the card for which the pin state should be recognized.
     * @return The recognized State (may be {@code RecognizedState.UNKNOWN}).
     * @throws InvocationTargetException In case the dispatched method throws an exception.
     * @throws DispatcherException In case a reflection error in the dispatcher occurs.
     */
    protected  Vector<Integer> readCredentials(ConnectionHandleType cHandle) throws InvocationTargetException,
	    DispatcherException {
	
	/* 1. Verify credential pin */
		    
	Transmit t = new Transmit();
	t.setSlotHandle(cHandle.getSlotHandle());
	InputAPDUInfoType inputAPDU = new InputAPDUInfoType();
	inputAPDU.setInputAPDU(credVerifyAPDU);
	t.getInputAPDUInfo().add(inputAPDU);
	TransmitResponse response = (TransmitResponse) dispatcher.deliver(t);

	byte[] responseAPDU = response.getOutputAPDU().get(0);

	RecognizedState state;
	if (ByteUtils.compare(RESPONSE_RC3, responseAPDU)) {
	    state = RecognizedState.PIN_activated_RC3;
	} else if (ByteUtils.compare(RESPONSE_DEACTIVATED, responseAPDU)) {
	    state = RecognizedState.PIN_deactivated;
	} else if (ByteUtils.compare(RESPONSE_RC2, responseAPDU)) {
	    state = RecognizedState.PIN_activated_RC2;
	} else if (ByteUtils.compare(RESPONSE_SUSPENDED, responseAPDU)) {
	    state = RecognizedState.PIN_suspended;
	} else if (ByteUtils.compare(RESPONSE_BLOCKED, responseAPDU)) {
	    state = RecognizedState.PIN_blocked;
	} else {
	    logger.error("Unhandled response to the PIN state recognition APDU: {}\n");
	    state = RecognizedState.UNKNOWN;
	}

	logger.info("State of the PIN: {}.", state);


	/* 2. Request the list of credentials */
	    
	inputAPDU.setInputAPDU(credListAPDU);
	t.getInputAPDUInfo().add(inputAPDU);
	response = (TransmitResponse) dispatcher.deliver(t);

	responseAPDU = response.getOutputAPDU().get(0);

	/* 3. Pack result into a list of credentials id's and
         * return */

        Vector<Integer> list = new Vector<Integer>();
        
        responseAPDU = Arrays.copyOfRange(responseAPDU, 0, responseAPDU.length - 2); // remove 0x9000    
                
        /* This part is taken from idemix_terminal, copyright Pim Vullers */
                                    
        for (int i = 0; i < responseAPDU.length; i = i+2) {
            int id = ((responseAPDU[i] & 0xff) << 8) | (responseAPDU[i + 1] & 0xff);
            
            if (id != 0) 
                list.add(id);
        }

	return list;
    }

    /**
     * Wait until a card of the specified card type was inserted.
     * 
     * @param cardType The type of the card that should be inserted.
     * @return The ConnectionHandle of the inserted card or null if no card was inserted.
     */
    protected ConnectionHandleType waitForCardType(String cardType) {
	String cardName = recognition.getTranslatedCardName(cardType);
	InsertCardDialog uc = new InsertCardDialog(gui, cardStates, cardType, cardName);
	return uc.show();
    }

    /**
     * Connect to the root application of the card specified with a connection handle using a empty CardApplicationPath
     * and afterwards a CardApplicationConnect.
     * 
     * @param cHandle
     *            The connection handle for the card to connect to root application.
     * @return The updated connection handle (now including a SlotHandle) or null if connecting went wrong.
     * @throws InvocationTargetException In case the dispatched method throws an exception.
     * @throws DispatcherException In case a reflection error in the dispatcher occurs.
     */
    protected ConnectionHandleType connectToRootApplication(ConnectionHandleType cHandle)
	throws InvocationTargetException, DispatcherException {

	// Perform a CardApplicationPath and CardApplicationConnect to connect to the card application
	CardApplicationPath cardApplicationPath = new CardApplicationPath();
	cardApplicationPath.setCardAppPathRequest(cHandle);
	CardApplicationPathResponse cardApplicationPathResponse = 
		(CardApplicationPathResponse) dispatcher.deliver(cardApplicationPath);

	// Check CardApplicationPathResponse
	try {
	    WSHelper.checkResult(cardApplicationPathResponse);
	} catch (WSException ex) {
	    logger.error("CardApplicationPath failed.", ex);
	    return null;
	}

	CardApplicationConnect cardApplicationConnect = new CardApplicationConnect();
	cardApplicationConnect.setCardApplicationPath(
		cardApplicationPathResponse.getCardAppPathResultSet().getCardApplicationPathResult().get(0));
	CardApplicationConnectResponse cardApplicationConnectResponse = 
		(CardApplicationConnectResponse) dispatcher.deliver(cardApplicationConnect);

	// Check CardApplicationConnectResponse
	try {
	    WSHelper.checkResult(cardApplicationConnectResponse);
	} catch (WSException ex) {
	    logger.error("CardApplicationConnect failed.", ex);
	    return null;
	}

	// Update ConnectionHandle. It now includes a SlotHandle.
	cHandle = cardApplicationConnectResponse.getConnectionHandle();

	return cHandle;
    }

    /**
     * Check if the selected card reader supports PACE.
     * In that case, the reader is a standard or comfort reader.
     *
     * @param connectionHandle Handle describing the IFD and reader.
     * @return true when card reader supports genericPACE, false otherwise.
     * @throws InvocationTargetException In case the dispatched method throws an exception.
     * @throws DispatcherException In case a reflection error in the dispatcher occurs.
     * @throws WSException In case request for the terminal capabilities returned an error.
     */
    protected boolean genericPACESupport(ConnectionHandleType connectionHandle) throws InvocationTargetException,
	    DispatcherException, WSException {
	// Request terminal capabilities
	GetIFDCapabilities capabilitiesRequest = new GetIFDCapabilities();
	capabilitiesRequest.setContextHandle(connectionHandle.getContextHandle());
	capabilitiesRequest.setIFDName(connectionHandle.getIFDName());
	GetIFDCapabilitiesResponse capabilitiesResponse = (GetIFDCapabilitiesResponse) dispatcher.deliver(capabilitiesRequest);
	WSHelper.checkResult(capabilitiesResponse);

	if (capabilitiesResponse.getIFDCapabilities() != null) {
	    List<SlotCapabilityType> capabilities = capabilitiesResponse.getIFDCapabilities().getSlotCapability();
	    // Check all capabilities for generic PACE
	    final String genericPACE = PACECapabilities.PACECapability.GenericPACE.getProtocol();
	    for (SlotCapabilityType capability : capabilities) {
		if (capability.getIndex().equals(connectionHandle.getSlotIndex())) {
		    for (String protocol : capability.getProtocol()) {
			if (protocol.equals(genericPACE)) {
			    return true;
			}
		    }
		}
	    }
	}

	// No PACE capability found
	return false;
    }

}
