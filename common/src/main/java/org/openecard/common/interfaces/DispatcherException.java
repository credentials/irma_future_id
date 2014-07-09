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

package org.openecard.common.interfaces;


/**
 * Exception class indicating reflection or runtime errors in the dispatcher.
 * This exception indicates a failure to read webservice interface definitions and invocations with unknown types.
 *
 * @author Tobias Wich <tobias.wich@ecsec.de>
 */
public class DispatcherException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Creates an instance and initializes the exception with a message.
     *
     * @param message The message describing the error.
     */
    public DispatcherException(String message) {
	super(message);
    }

    /**
     * Creates an instance and initializes the exception with a cause.
     *
     * @param cause The exception causing the error.
     */
    public DispatcherException(Throwable cause) {
	super(cause);
    }

    /**
     * Creates an instance and initializes the exception with a message and a cause.
     *
     * @param message The message describing the error.
     * @param cause The exception causing the error.
     */
    public DispatcherException(String message, Throwable cause) {
	super(message, cause);
    }

}
