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

import iso.std.iso_iec._24727.tech.schema.Transmit;
import iso.std.iso_iec._24727.tech.schema.TransmitResponse;
import iso.std.iso_iec._24727.tech.schema.ConnectionHandleType;
import iso.std.iso_iec._24727.tech.schema.InputAPDUInfoType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Vector;
import org.openecard.common.util.StringUtils;
import org.openecard.common.I18n;
import org.openecard.common.interfaces.Dispatcher;
import org.openecard.common.interfaces.DispatcherException;
import org.openecard.gui.UserConsent;
import org.openecard.gui.UserConsentNavigator;
import org.openecard.gui.definition.PasswordField;
import org.openecard.gui.definition.Step;
import org.openecard.gui.definition.Text;
import org.openecard.gui.definition.UserConsentDescription;
import org.openecard.gui.executor.ExecutionEngine;
import org.openecard.gui.executor.StepAction;
import org.openecard.plugins.abcplugin.RecognizedState;
import org.openecard.plugins.abcplugin.IdemixLogEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Implements a dialog for unblocking the PIN.
 * This dialog guides the user through the process needed for unblocking the PIN.
 * 
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 */
public class ChangeAdminPinDialog {

    private final I18n lang = I18n.getTranslation("abcplugin");
    private static final Logger logger = LoggerFactory.getLogger(ChangeAdminPinDialog.class);

    private static final String TITLE = "action.readcred.userconsent.title";
    private static final String PUKSTEP_DESCRIPTION = "action.readcred.userconsent.pukstep.description";
    private static final String PUKSTEP_NATIVE_DESCRIPTION = "action.readcred.userconsent.pukstep.native_description";
    private static final String PUKSTEP_TITLE = "action.readcred.userconsent.pukstep.title";
    private static final String PUKSTEP_PUK = "action.readcred.userconsent.pukstep.puk";
    private static final String ERRORSTEP_TITLE = "action.readcred.userconsent.errorstep.title";
    private static final String ERRORSTEP_DESCRIPTION = "action.readcred.userconsent.errorstep.description";
    private static final String SUCCESSSTEP_TITLE = "action.readcred.userconsent.successstep.title";
    private static final String SUCCESSSTEP_DESCRIPTION = "action.readcred.userconsent.successstep.description";

    private static final byte[] credListAPDU = StringUtils.toByteArray("803A0000"); 

    private final UserConsent gui;
    private final ConnectionHandleType conHandle;
    private RecognizedState state;
    private boolean capturePin;
    private Dispatcher dispatcher;

    private Vector<Integer> credentials;

    // GUI element IDs
    public static final String PUK_FIELD = "PUK_FIELD";
    public static final int N_IRMA_CREDENTIALS = 15;

    /**
     * Creates a new instance of UnblockPINUserConsent.
     * 
     * @param gui The UserConsent to show on
     * @param capturePin True if the PIN has to be captured by software else false
     * @param conHandle to get the requested card type from
     * @param dispatcher The Dispatcher to use
     * @param state The State of the PIN
     */
    public ChangeAdminPinDialog(UserConsent gui, Dispatcher dispatcher, ConnectionHandleType conHandle) {
	this.gui = gui;
	this.conHandle = conHandle;
	this.dispatcher = dispatcher;
    }

    private UserConsentDescription createUserConsentDescription() {
	UserConsentDescription uc = new UserConsentDescription(lang.translationForKey(TITLE));

	uc.getSteps().addAll(createSteps());

	return uc;
    }

    /**
     * Create the list of steps depending on the state of the pin.
     * 
     * @return list of steps for the Dialog
     */
    private List<Step> createSteps() {
	List<Step> steps = new ArrayList<Step>();
        
	Step puk = createPUKStep();                        
        steps.add(puk);
                                
        Step successStep = createSuccessStep();
        steps.add(successStep);
	
	return steps;
    }

    /**
     * Create the step that informs the user that everything went fine.
     *
     * @return Step showing success message
     */
    private Step createSuccessStep() {
            
	Step successStep = new Step("success", "Operations log");
        Vector<Integer> list = new Vector<Integer>();
        Vector<byte[]> log_list = new Vector<byte[]>();
                
	byte[] responseAPDU = null;

        byte[] get_log_1 = new byte[] { (byte) 0x80, (byte) 0x3B, (byte) 0x00, (byte) 0x00 };
        byte[] get_log_2 = new byte[] { (byte) 0x80, (byte) 0x3B, (byte) 0x0F, (byte) 0x00 };

        int LOG_SIZE = 30;
        int LOG_ENTRY_SIZE = 16;
        
        byte LOG_ENTRIES_PER_APDU = 255 / 16;

        try {

	    for (byte start_entry = 0; start_entry < LOG_SIZE;
                start_entry = (byte) (start_entry + LOG_ENTRIES_PER_APDU)) {

                get_log_2[2] = (byte) start_entry;

                Transmit t = new Transmit();
                t.setSlotHandle(conHandle.getSlotHandle());
                InputAPDUInfoType inputAPDU = new InputAPDUInfoType();
                inputAPDU.setInputAPDU(get_log_2);
                t.getInputAPDUInfo().add(inputAPDU);
                TransmitResponse response = (TransmitResponse) dispatcher.deliver(t);

                byte[] responseAPDU_1 = response.getOutputAPDU().get(0);

                for (int entry = 0; entry < LOG_ENTRIES_PER_APDU
                    && entry + start_entry < LOG_SIZE; entry++) {
                                                                     
                    byte[] log_entry = Arrays.copyOfRange(responseAPDU_1, LOG_ENTRY_SIZE
                        * entry, LOG_ENTRY_SIZE * (entry + 1));
                                                                                                              
                    StringBuffer result = new StringBuffer();                                    
                    
                    for (byte b:log_entry) 
                        result.append(String.format("%02X", b));
                                     
                    log_list.add(log_entry);
                    IdemixLogEntry logEntry  = new IdemixLogEntry(log_entry);
                    logEntry.print();
                }                           
            }

	} catch (DispatcherException e) {
		    logger.error("Transmission of the get credentials APDU failed", e);
	        return null;

	} catch (java.lang.reflect.InvocationTargetException e) {
		    logger.error("Transmission of the get credentials APDU failed", e);
	        return null;
	}

        for(int i = 0; i < log_list.size(); i++) {
            IdemixLogEntry logEntry  = new IdemixLogEntry(log_list.get(i));

            Text t = new Text();
            t.setText("Log slot " + i + " : " + logEntry.print());

            successStep.getInputInfoUnits().add(t);
        }

	return successStep;
    }

    /**
     * Create the step that informs the user that something went wrong.
     * 
     * @return Step with error description
     */
    private Step createErrorStep() {
	Step errorStep = new Step("insert-card", lang.translationForKey(ERRORSTEP_TITLE));
	Text i1 = new Text();
	i1.setText(lang.translationForKey(ERRORSTEP_DESCRIPTION));
	errorStep.getInputInfoUnits().add(i1);
	return errorStep;
    }

    /**
     * Create the step that asks the user to insert the PUK.
     * 
     * @return Step for PUK entry
     */
    private Step createPUKStep() {
	Step pukStep = new Step("insert-card", "Type your admin PIN");

        PasswordField pukField = new PasswordField(PUK_FIELD);
        pukStep.getInputInfoUnits().add(pukField);
	
	StepAction pinAction = new PUKStepAction(capturePin, conHandle.getSlotHandle(), dispatcher, pukStep);
	pukStep.setAction(pinAction);

	return pukStep;
    }

    /**
     * Shows this Dialog.
     */
    public void show() {
	UserConsentNavigator ucr = gui.obtainNavigator(createUserConsentDescription());
	ExecutionEngine exec = new ExecutionEngine(ucr);
	exec.process();
    }
}
