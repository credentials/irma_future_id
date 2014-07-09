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

import iso.std.iso_iec._24727.tech.schema.ConnectionHandleType;
import iso.std.iso_iec._24727.tech.schema.Disconnect;
import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.Process;
import org.openecard.addon.Context;
import org.openecard.addon.ActionInitializationException;
import org.openecard.common.WSHelper.WSException;
import org.openecard.common.interfaces.DispatcherException;
import org.openecard.plugins.abc4trustplugin.gui.ChangePINDialog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Action for loading the user's webservice for ABC4Trust
 * 
 * @author Antonio de la Piedra <a.delapiedra@cs.ru.nl>
 */
public class LoadUserWebServiceAction extends AbstractPINAction {

    private static final Logger logger = LoggerFactory.getLogger(LoadUserWebServiceAction.class);
    private static final String userWebServicePath = "../../.../../Code/core-abce/abce-services/tmp/"; 
    private static final String userWebServiceName = "../../.../../Code/core-abce/abce-services/tmp/start_user.sh"; 
    
    @Override
    public void execute() {
        try {
            Process pr = Runtime.getRuntime().exec(userWebServiceName, null, new File(userWebServicePath));
        } catch (Exception e) {
            logger.error("Failed to load the user's webservice.", e);
        }
    }

    @Override
    public void init(Context ctx) throws ActionInitializationException {
	this.dispatcher = ctx.getDispatcher();
	this.gui = ctx.getUserConsent();
	this.recognition = ctx.getRecognition();
	this.cardStates = ctx.getCardStates();
    }

    @Override
    public void destroy() {
	// ignore
    }

}
