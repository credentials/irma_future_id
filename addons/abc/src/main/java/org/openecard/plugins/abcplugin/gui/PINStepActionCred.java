/****************************************************************************
 * Copyright (C) 2012 HS Coburg.
 * Copyright (C) 2014 Radboud University Nijmegen.
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

package org.openecard.plugins.abcplugin.gui;

import iso.std.iso_iec._24727.tech.schema.Transmit;
import iso.std.iso_iec._24727.tech.schema.TransmitResponse;
import iso.std.iso_iec._24727.tech.schema.InputAPDUInfoType;
import iso.std.iso_iec._24727.tech.schema.ConnectionHandleType;
import iso.std.iso_iec._24727.tech.schema.ControlIFD;
import iso.std.iso_iec._24727.tech.schema.DIDAuthenticationDataType;
import iso.std.iso_iec._24727.tech.schema.EstablishChannel;
import iso.std.iso_iec._24727.tech.schema.EstablishChannelResponse;
import iso.std.iso_iec._24727.tech.schema.PasswordAttributesType;
import iso.std.iso_iec._24727.tech.schema.PasswordTypeType;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.util.Map;
import javax.xml.parsers.ParserConfigurationException;
import org.openecard.common.ECardConstants;
import org.openecard.common.I18n;
import org.openecard.common.WSHelper;
import org.openecard.common.WSHelper.WSException;
import org.openecard.common.anytype.AuthDataMap;
import org.openecard.common.anytype.AuthDataResponse;
import org.openecard.common.apdu.ResetRetryCounter;
import org.openecard.common.apdu.exception.APDUException;
import org.openecard.common.ifd.anytype.PACEInputType;
import org.openecard.common.interfaces.Dispatcher;
import org.openecard.common.interfaces.DispatcherException;
import org.openecard.common.util.ByteUtils;
import org.openecard.common.util.StringUtils;
import org.openecard.gui.StepResult;
import org.openecard.gui.definition.PasswordField;
import org.openecard.gui.definition.Step;
import org.openecard.gui.executor.ExecutionResults;
import org.openecard.gui.executor.StepAction;
import org.openecard.gui.executor.StepActionResult;
import org.openecard.gui.executor.StepActionResultStatus;
import org.openecard.ifd.scio.IFDException;
import org.openecard.ifd.scio.reader.PCSCFeatures;
import org.openecard.ifd.scio.reader.PCSCPinModify;
import org.openecard.plugins.abcplugin.RecognizedState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static iso.std.iso_iec._24727.tech.schema.PasswordTypeType.ASCII_NUMERIC;


/**
 * StepAction for performing PACE with the PIN and modify it.
 * <br/> This StepAction tries to perform PACE with the PIN as often as possible in dependence of the retry counter.
 * <br/> If PACE was executed successful the PIN is modified.
 * <br/> If the retry counter reaches 1 the CANEntryStep will be shown.
 * 
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 * @author Antonio de la Piedra <a.delapiedra@cs.ru.nl>
 */
public class PINStepActionCred extends StepAction {

    // translation and logger
    private static final Logger logger = LoggerFactory.getLogger(PINStepActionCred.class);
    private final I18n lang = I18n.getTranslation("pinplugin");

    // translation constants
    private static final String PINSTEP_TITLE = "action.changepin.userconsent.pinstep.title";
    private static final String CANSTEP_TITLE = "action.changepin.userconsent.canstep.title";

    private static final String ISO_8859_1 = "ISO-8859-1";
    private static final String PIN_ID_PIN = "3";

    private final boolean capturePin;
    private final ConnectionHandleType conHandle;
    private final Dispatcher dispatcher;

    private int retryCounter;
    private String oldPIN;
    private byte[] newPIN;
    private byte[] newPINRepeat;

    /**
     * Create a new instance of PINStepActionCred.
     *
     * @param capturePin True if the PIN has to be captured by software else false
     * @param conHandle The unique ConnectionHandle for the card connection
     * @param step the step this action belongs to
     * @param dispatcher The Dispatcher to use
     * @param retryCounter RetryCounter of the PIN
     */
    public PINStepActionCred(boolean capturePin, ConnectionHandleType conHandle, Dispatcher dispatcher, Step step, int retryCounter) {
	super(step);
	this.capturePin = capturePin;
	this.conHandle = conHandle;
	this.dispatcher = dispatcher;
	this.retryCounter = retryCounter;
    }

    @Override
    public StepActionResult perform(Map<String, ExecutionResults> oldResults, StepResult result) {
	if (result.isBack()) 
	    return new StepActionResult(StepActionResultStatus.BACK);
	
        ExecutionResults executionResults = oldResults.get(getStepID());
        verifyUserInput(executionResults);
        
        return new StepActionResult(StepActionResultStatus.NEXT);
    }

    /**
     * Create the step that asks the user to insert the CAN.
     * 
     * @return Step for CAN entry
     */
    private Step createCANReplacementStep() {
	String title = lang.translationForKey(CANSTEP_TITLE);
	RecognizedState state = RecognizedState.PIN_suspended;
	CANEntryStep canStep = new CANEntryStep("can-entry", title , capturePin, state, false, false);
	StepAction pinAction = new CANStepAction(capturePin, conHandle, dispatcher, canStep, state);
	canStep.setAction(pinAction);
	return canStep;
    }

    /**
     * Send a ModifyPIN-PCSC-Command to the Terminal.
     * 
     * @throws IFDException If building the Command fails.
     * @throws InvocationTargetException If the ControlIFD command fails.
     * @throws DispatcherException If an error in the dispatcher occurs.
     */
    private void sendModifyPIN() throws IFDException, InvocationTargetException, DispatcherException {
	PasswordAttributesType pwdAttr = create(true, ASCII_NUMERIC, 6, 6, 6);
	pwdAttr.setPadChar(new byte[] { (byte) 0x3F });
	PCSCPinModify ctrlStruct = new PCSCPinModify(pwdAttr, StringUtils.toByteArray("002C0203"));
	byte[] structData = ctrlStruct.toBytes();

	ControlIFD controlIFD = new ControlIFD();
	controlIFD.setCommand(ByteUtils.concatenate((byte) PCSCFeatures.MODIFY_PIN_DIRECT, structData));
	controlIFD.setContextHandle(conHandle.getContextHandle());
	controlIFD.setIFDName(conHandle.getIFDName());
	dispatcher.deliver(controlIFD);
    }

    /**
     * Send a ResetRetryCounter-APDU.
     * 
     * @throws APDUException if the RRC-APDU could not be sent successfully
     */
    private void sendResetRetryCounter() throws APDUException {
	ResetRetryCounter apdu = new ResetRetryCounter(newPIN, (byte) 0x03);
	apdu.transmit(dispatcher, conHandle.getSlotHandle());
    }

    private static PasswordAttributesType create(boolean needsPadding, PasswordTypeType pwdType, int minLen,
	    int storedLen, int maxLen) {
	PasswordAttributesType r = new PasswordAttributesType();
	r.setMinLength(BigInteger.valueOf(minLen));
	r.setStoredLength(BigInteger.valueOf(storedLen));
	r.setPwdType(pwdType);
	if (needsPadding) {
	    r.getPwdFlags().add("needs-padding");
	}
	r.setMaxLength(BigInteger.valueOf(maxLen));
	return r;
    }

    /**
     * Verify the input of the user (e.g. no empty mandatory fields, pin length, allowed charset).
     * 
     * @param executionResults The results containing the OutputInfoUnits of interest.
     * @return True if the input of the user could be verified, else false.
     */
    private boolean verifyUserInput(ExecutionResults executionResults) {
	// TODO: check pin length and possibly allowed charset with CardInfo file

	PasswordField fieldOldPIN = (PasswordField) executionResults.getResult(ChangePINStep.OLD_PIN_FIELD);
	PasswordField fieldNewPIN = (PasswordField) executionResults.getResult(ChangePINStep.NEW_PIN_FIELD);
	
	byte[] new_pin_hex_byte = null;
	byte[] old_pin_hex_byte = null;

        /* First APDU: verify_apdu << "0020000108" << admin_pin_hex.str() << "0000"; */

	byte[] apdu_1_p_1 = {(byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0x01, (byte) 0x08};
	byte[] apdu_1_p_2 = {(byte) 0x00, (byte) 0x00};

	byte[] apduChangePINCred_1 = new byte[apdu_1_p_1.length + 6 + apdu_1_p_2.length];

	/* Second APDU: update_cred_pin_apdu << "0024000008" << new_pin_hex.str() << "00000000"; */

	byte[] apdu_2_p_1 = {(byte) 0x00, (byte) 0x24, (byte) 0x00, (byte) 0x00, (byte) 0x08};
	byte[] apdu_2_p_2 = {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};

	byte[] apduChangePINCred_2 = new byte[apdu_2_p_1.length + 4 + apdu_2_p_2.length];

	try {

	    String new_pin_hex = String.format("%x", new BigInteger(1, fieldNewPIN.getValue().getBytes("UTF-8")));

	    int len = new_pin_hex.length();
	
	    new_pin_hex_byte = new byte[len / 2];
           
	    for (int i = 0; i < len; i += 2) 
                new_pin_hex_byte[i / 2] = (byte) ((Character.digit(new_pin_hex.charAt(i), 16) << 4)
                + Character.digit(new_pin_hex.charAt(i+1), 16));


            String old_pin_hex = String.format("%x", new BigInteger(1, fieldOldPIN.getValue().getBytes("UTF-8")));

            len = old_pin_hex.length();
	
            old_pin_hex_byte = new byte[len / 2];
           
            for (int i = 0; i < len; i += 2) 
                old_pin_hex_byte[i / 2] = (byte) ((Character.digit(old_pin_hex.charAt(i), 16) << 4)
                + Character.digit(old_pin_hex.charAt(i+1), 16));

            } catch(java.io.UnsupportedEncodingException e) {
                logger.error("Transformation from string to byte array (old/new PIN) failed.", e);
                return false;
        }

        /* Craft first APDU */

	System.arraycopy(apdu_1_p_1, 0, apduChangePINCred_1, 0, apdu_1_p_1.length);
	System.arraycopy(old_pin_hex_byte, 0, apduChangePINCred_1, apdu_1_p_1.length, old_pin_hex_byte.length);
	System.arraycopy(apdu_1_p_2, 0, apduChangePINCred_1, apdu_1_p_1.length + old_pin_hex_byte.length, apdu_1_p_2.length);

	/* Craft second APDU */

	System.arraycopy(apdu_2_p_1, 0, apduChangePINCred_2, 0, apdu_2_p_1.length);
	System.arraycopy(new_pin_hex_byte, 0, apduChangePINCred_2, apdu_2_p_1.length, new_pin_hex_byte.length);
	System.arraycopy(apdu_2_p_2, 0, apduChangePINCred_2, apdu_2_p_1.length + new_pin_hex_byte.length, apdu_2_p_2.length);

        try {

            /* Sending first APDU */

	    Transmit tr = new Transmit();
	    tr.setSlotHandle(conHandle.getSlotHandle());
	    InputAPDUInfoType inputAPDU = new InputAPDUInfoType();
	    inputAPDU.setInputAPDU(apduChangePINCred_1);
	    tr.getInputAPDUInfo().add(inputAPDU);
	    TransmitResponse response = (TransmitResponse) dispatcher.deliver(tr);

	    byte[] responseAPDU = response.getOutputAPDU().get(0);

	    /* TODO: Parse response */

            /* Sending second APDU */

	    tr = new Transmit();
	    tr.setSlotHandle(conHandle.getSlotHandle());
	    inputAPDU = new InputAPDUInfoType();
	    inputAPDU.setInputAPDU(apduChangePINCred_2);
	    tr.getInputAPDUInfo().add(inputAPDU);
	    response = (TransmitResponse) dispatcher.deliver(tr);

	    responseAPDU = response.getOutputAPDU().get(0);

	} catch (DispatcherException e) {
            logger.error("Transmission of the get credentials APDU failed", e);
            return false;

	} catch (java.lang.reflect.InvocationTargetException e) {
            logger.error("Transmission of the get credentials APDU failed", e);
            return false;
	}

	return true;
    }

    /**
     * Create the step that asks the user to insert the old and new pins.
     * 
     * @return Step for PIN entry
     */
    private Step createPINReplacementStep(boolean enteredWrong, boolean verifyFailed) {
	String title = lang.translationForKey(PINSTEP_TITLE);
	Step changePINStep = new ChangePINStep("pin-entry", title, capturePin, retryCounter, enteredWrong, verifyFailed);
	StepAction pinAction = new PINStepActionCred(capturePin, conHandle, dispatcher, changePINStep, retryCounter);
	changePINStep.setAction(pinAction);
	return changePINStep;
    }

}
