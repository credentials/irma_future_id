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

package org.openecard.control.module.status;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.util.Map;
import org.openecard.addon.EventHandler;
import org.openecard.common.util.HttpRequestLineUtils;
import org.openecard.ws.schema.StatusChange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Handles the generic part of status change requests.
 *
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 */
public class WaitForChangeHandler {

    private static final Logger logger = LoggerFactory.getLogger(StatusHandler.class);

    private final EventHandler eventHandler;

    /**
     * Creates a new WaitForChangeHandler.
     *
     * @param eventHandler to query for a status change
     */
    public WaitForChangeHandler(EventHandler eventHandler) {
	this.eventHandler = eventHandler;
    }

    /**
     * Returns the next status change for the session given in the status request.
     *
     * @param statusRequest status request containing session identifier
     * @return status change for the session
     */
    public StatusChange getStatusChange(StatusChangeRequest statusRequest) {
	return eventHandler.next(statusRequest.getSessionIdentifier());
    }

    /**
     *
     * @param requestURI Status request URI
     * @return StatusChangeRequest containing an mandatory session identifier
     * @throws UnsupportedEncodingException
     * @throws MalformedURLException if mandatory parameters or values are missing
     */
    public StatusChangeRequest parseStatusChangeRequestURI(URI requestURI) throws UnsupportedEncodingException,
	    MalformedURLException {
	Map<String, String> queries = HttpRequestLineUtils.transform(requestURI.getRawQuery());
	String sessionIdentfier = null;

	for (Map.Entry<String, String> next : queries.entrySet()) {
	    String name = next.getKey();
	    String value = next.getValue();

	    if (name.startsWith("session")) {
		if (value != null && !value.isEmpty()) {
		    sessionIdentfier = value;
		} else {
		    throw new IllegalArgumentException("Malformed StatusURL");
		}
	    } else {
		logger.debug("Unknown query element: {}", name);
	    }
	}
	if (sessionIdentfier == null) {
	    throw new MalformedURLException("RequestURI is missing mandatory session parameter.");
	} else {
	    return new StatusChangeRequest(sessionIdentfier);
	}
    }

}
