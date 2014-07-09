/****************************************************************************
 * Copyright (C) 2013 ecsec GmbH.
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

package org.openecard.control.module.tctoken;

import iso.std.iso_iec._24727.tech.schema.ConnectionHandleType;
import iso.std.iso_iec._24727.tech.schema.StartPAOS;
import iso.std.iso_iec._24727.tech.schema.StartPAOSResponse;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.util.concurrent.Callable;
import org.openecard.common.ECardConstants;
import org.openecard.common.interfaces.Dispatcher;
import org.openecard.common.interfaces.DispatcherException;
import org.openecard.transport.paos.PAOS;
import org.openecard.transport.paos.PAOSException;


/**
 *
 * @author Tobias Wich <tobias.wich@ecsec.de>
 */
public class PAOSTask implements Callable<StartPAOSResponse> {

    private final Dispatcher dispatcher;
    private final ConnectionHandleType connectionHandle;
    private final TCTokenRequest tokenRequest;

    public PAOSTask(Dispatcher dispatcher, ConnectionHandleType connectionHandle, TCTokenRequest tokenRequest) {
	this.dispatcher = dispatcher;
	this.connectionHandle = connectionHandle;
	this.tokenRequest = tokenRequest;
    }


    @Override
    public StartPAOSResponse call()
	    throws MalformedURLException, PAOSException, DispatcherException, InvocationTargetException,
	    ConnectionError {
	try {
	    TlsConnectionHandler tlsHandler = new TlsConnectionHandler(dispatcher, tokenRequest, connectionHandle);
	    tlsHandler.setUpClient();

	    // Set up PAOS connection
	    PAOS p = new PAOS(dispatcher, tlsHandler);

	    // Create StartPAOS message
	    StartPAOS sp = new StartPAOS();
	    sp.setProfile(ECardConstants.Profile.ECARD_1_1);
	    sp.getConnectionHandle().add(connectionHandle);
	    sp.setSessionIdentifier(tlsHandler.getSessionId());

	    return p.sendStartPAOS(sp);
	} finally {
	    TCTokenHandler.disconnectHandle(dispatcher, connectionHandle);
	}
    }


}
