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

package org.openecard.control.binding.http.handler;

import org.openecard.apache.http.protocol.HttpRequestHandler;


/**
 * @author Moritz Horsch <horsch@cdc.informatik.tu-darmstadt.de>
 */
public abstract class HttpControlHandler implements HttpRequestHandler {

    /** Identifier to register the handler for */
    protected String resource;

    /**
     * Create a new HttpControlHandler.
     *
     * @param resource Identifier
     */
    protected HttpControlHandler(String resource) {
	this.resource = resource;
    }

    /**
     * Return the ID to register the handler for.
     *
     * @return Identifier
     */
    public String getResourcePath() {
	return resource;
    }

}
