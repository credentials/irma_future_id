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

import java.net.URL;
import org.openecard.bouncycastle.crypto.tls.Certificate;


/**
 * Verifier interface for the TCTokenGrabber class.
 * The interface can be used to add security checks like e.g. the ones defined in TR-03112.
 *
 * @author Tobias Wich <tobias.wich@ecsec.de>
 */
public interface CertificateVerifier {

    /**
     * Result indicating whether to proceed or stop execution.
     * Errors in the validation are signaled with exceptions in the {@code verify} function itself.
     */
    public static enum VerifierResult {
	CONTINE,
	FINISH;
    }

    /**
     * Verify the given tuple.
     *
     * @param url Url of the last connection.
     * @param cert Certificate chain of the last connection.
     * @return Status indicating how to proceed.
     * @throws ControlException Thrown in case the validation failed.
     */
    public VerifierResult verify(URL url, Certificate cert) throws ControlException;

}
