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

package org.openecard.common.sal.exception;

import org.openecard.common.ECardConstants;
import org.openecard.common.ECardException;


/**
 *
 * @author Tobias Wich <tobias.wich@ecsec.de>
 */
public final class UnknownProtocolException extends ECardException {

    private static final long serialVersionUID = 1L;

    public UnknownProtocolException(String message) {
	makeException(this, ECardConstants.Minor.SAL.PROTOCOL_NOT_RECOGNIZED, message);
    }

    public UnknownProtocolException(String protocol, String objectString) {
	this("No protocol step available for " + protocol + " in protocol " + objectString + ".");
    }

}
