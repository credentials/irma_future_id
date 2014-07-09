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

package org.openecard.ifd.protocol.pace.gui;

import java.util.Map;
import org.openecard.common.I18n;
import org.openecard.gui.definition.PasswordField;
import org.openecard.gui.definition.Step;
import org.openecard.gui.definition.Text;
import org.openecard.gui.executor.ExecutionResults;
import org.openecard.ifd.protocol.pace.common.PasswordID;


/**
 * Implements a GUI user consent step for the PIN.
 *
 * @author Moritz Horsch <horsch@cdc.informatik.tu-darmstadt.de>
 */
public class PINStep {

    // GUI translation constants
    private static final String TITLE = "step_pace_title";
    private static final String DESCRIPTION = "step_pace_description";

    private I18n lang = I18n.getTranslation("pace");
    private Step step = new Step(lang.translationForKey(TITLE));
    private GUIContentMap content;
    private String passwordType;

    /**
     * Creates a new GUI user consent step for the PIN.
     *
     * @param content GUI content
     */
    public PINStep(GUIContentMap content) {
	this.content = content;

	passwordType = PasswordID.parse((Byte) (content.get(GUIContentMap.ELEMENT.PIN_ID))).getString();
	initialize();
    }

    private void initialize() {
	String stepTitle = lang.translationForKey(TITLE);
	stepTitle = stepTitle.replaceFirst("%s", passwordType);
	step.setTitle(stepTitle);

	String decriptionText = lang.translationForKey(DESCRIPTION);
	decriptionText = decriptionText.replaceFirst("%s", passwordType);

	Text description = new Text();
	description.setText(decriptionText);
	step.getInputInfoUnits().add(description);

	PasswordField pinInputField = new PasswordField(passwordType);
	pinInputField.setDescription(lang.translationForKey(passwordType));
	step.getInputInfoUnits().add(pinInputField);
    }

    /**
     * Returns the generated step.
     *
     * @return Step
     */
    public Step getStep() {
	return step;
    }

    /**
     * Processes the results of step.
     *
     * @param results Results
     */
    public void processResult(Map<String, ExecutionResults> results) {
	ExecutionResults executionResults = results.get(step.getID());

	if (executionResults == null) {
	    return;
	}

	PasswordField p = (PasswordField) executionResults.getResult(passwordType);
	content.add(GUIContentMap.ELEMENT.PIN, p.getValue());
    }

}
