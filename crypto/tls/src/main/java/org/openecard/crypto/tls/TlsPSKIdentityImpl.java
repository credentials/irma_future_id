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

package org.openecard.crypto.tls;

import org.openecard.bouncycastle.crypto.tls.TlsPSKIdentity;


/**
 *
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 * @author Simon Potzernheim <potzernheim@hs-coburg.de>
 */
public class TlsPSKIdentityImpl implements TlsPSKIdentity {

    private byte[] identity;
    private byte[] psk;

    public TlsPSKIdentityImpl(byte[] identity, byte[] psk) {
	this.identity = identity;
	this.psk = psk;
    }

    @Override
    public byte[] getPSK() {
	return psk;
    }

    @Override
    public byte[] getPSKIdentity() {
	return identity;
    }

    @Override
    public void notifyIdentityHint(byte[] arg0) {
	// ignore
    }

    @Override
    public void skipIdentityHint() {
	// OK
    }

}
