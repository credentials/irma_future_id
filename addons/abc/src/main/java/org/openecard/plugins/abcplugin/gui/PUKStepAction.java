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

package org.openecard.plugins.abcplugin.gui;

import iso.std.iso_iec._24727.tech.schema.DIDAuthenticationDataType;
import iso.std.iso_iec._24727.tech.schema.DestroyChannel;
import iso.std.iso_iec._24727.tech.schema.EstablishChannel;
import iso.std.iso_iec._24727.tech.schema.EstablishChannelResponse;
import iso.std.iso_iec._24727.tech.schema.Transmit;
import iso.std.iso_iec._24727.tech.schema.TransmitResponse;
import iso.std.iso_iec._24727.tech.schema.InputAPDUInfoType;
import java.lang.reflect.InvocationTargetException;
import java.lang.Character;
import java.util.Map;
import java.math.BigInteger;
import javax.xml.parsers.ParserConfigurationException;
import org.openecard.common.ECardConstants;
import org.openecard.common.WSHelper;
import org.openecard.common.WSHelper.WSException;
import org.openecard.common.anytype.AuthDataMap;
import org.openecard.common.anytype.AuthDataResponse;
import org.openecard.common.ifd.anytype.PACEInputType;
import org.openecard.common.interfaces.Dispatcher;
import org.openecard.common.interfaces.DispatcherException;
import org.openecard.common.util.StringUtils;
import org.openecard.gui.StepResult;
import org.openecard.gui.definition.PasswordField;
import org.openecard.gui.definition.Step;
import org.openecard.gui.executor.ExecutionResults;
import org.openecard.gui.executor.StepAction;
import org.openecard.gui.executor.StepActionResult;
import org.openecard.gui.executor.StepActionResultStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;


/**
 * StepAction for obtaining the administration PIN.
 *
 * @author Antonio de la Piedra <a.delapiedra@cs.ru.nl>
 */
public class PUKStepAction extends StepAction {

    private static final Logger logger = LoggerFactory.getLogger(PUKStepAction.class);

    private static final String PIN_ID_PUK = "4";

    private static final byte[] credVerifyAPDU = StringUtils.toByteArray("0020000108");
    private static final byte[] credListAPDU = StringUtils.toByteArray("803A0000"); 
    private static final byte[] endAPDU = StringUtils.toByteArray("0000"); 

    private final boolean capturePin;
    private final byte[] slotHandle;
    private final Dispatcher dispatcher;

    private String puk;

    private byte[] responseCredentials;

    /**
     * Create a new instance of PUKStepAction.
     *
     * @param capturePin True if the PIN has to be captured by software else false
     * @param slotHandle The unique SlotHandle for the card to use
     * @param step the step this action belongs to
     * @param dispatcher The Dispatcher to use
     */
    public PUKStepAction(boolean capturePin, byte[] slotHandle, Dispatcher dispatcher, Step step) {
	super(step);
	this.capturePin = capturePin;
	this.slotHandle = slotHandle;
	this.dispatcher = dispatcher;
    }

    @Override
    public StepActionResult perform(Map<String, ExecutionResults> oldResults, StepResult result)
         {
        
         if (result.isBack()) {
             return new StepActionResult(StepActionResultStatus.BACK);
         }

         ExecutionResults executionResults = oldResults.get(getStepID());        
         verifyUserInput(executionResults);

         try {
          String pin_hex = String.format("%x", new BigInteger(1, puk.getBytes("UTF-8")));

	  int len = pin_hex.length();
	  byte[] pin_hex_byte = new byte[len / 2];
           
          for (int i = 0; i < len; i += 2) 
           pin_hex_byte[i / 2] = (byte) ((Character.digit(pin_hex.charAt(i), 16) << 4)
            + Character.digit(pin_hex.charAt(i+1), 16));

          Transmit t = new Transmit();
          t.setSlotHandle(slotHandle);
             
          InputAPDUInfoType inputAPDU = new InputAPDUInfoType();
	
          byte[] combined = new byte[credVerifyAPDU.length + pin_hex_byte.length];
          
          System.arraycopy(credVerifyAPDU, 0, combined, 0         , credVerifyAPDU.length);
          System.arraycopy(pin_hex_byte, 0, combined, credVerifyAPDU.length, pin_hex_byte.length);

          byte[] finalVerify = new byte[combined.length + endAPDU.length];
          
          System.arraycopy(combined, 0, finalVerify, 0         , combined.length);
          System.arraycopy(endAPDU, 0, finalVerify, combined.length, endAPDU.length);
	
          inputAPDU.setInputAPDU(finalVerify);

          t.getInputAPDUInfo().add(inputAPDU);
	
          TransmitResponse response = (TransmitResponse) dispatcher.deliver(t);

          byte[] responseAPDU = response.getOutputAPDU().get(0);



         } catch (java.io.UnsupportedEncodingException e) {
            logger.error("The credential PIN cannot be parsed.", e);

            return null;
         } catch (Exception e) {
             logger.error("The credential PIN verification failed.", e);

             return null;
         }

        try {

	Transmit tr = new Transmit();
	tr.setSlotHandle(slotHandle);
	InputAPDUInfoType inputAPDU = new InputAPDUInfoType();
	inputAPDU.setInputAPDU(credListAPDU);
	tr.getInputAPDUInfo().add(inputAPDU);
	TransmitResponse response = (TransmitResponse) dispatcher.deliver(tr);

	this.responseCredentials = response.getOutputAPDU().get(0);

	} catch (DispatcherException e) {
		    logger.error("Transmission of the get credentials APDU failed", e);
	        return null;

	} catch (java.lang.reflect.InvocationTargetException e) {
		    logger.error("Transmission of the get credentials APDU failed", e);
	        return null;
	}
 
        return new StepActionResult(StepActionResultStatus.NEXT);
    }

    /**
     * Verify the input of the user (e.g. no empty mandatory fields, pin length, allowed charset).
     * 
     * @param executionResults The results containing the OutputInfoUnits of interest.
     * @return True if the input of the user could be verified, else false
     */
    private boolean verifyUserInput(ExecutionResults executionResults) {

	PasswordField pukField = (PasswordField) executionResults.getResult(UnblockPINDialog.PUK_FIELD);

	puk = pukField.getValue();
	
	if (puk.isEmpty()) {
	    return false;
	}

	return true;
    }

    public byte[] getCredentials() {
     return this.responseCredentials;
    }
}
