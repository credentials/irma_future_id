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

package org.openecard.crypto.tls;

import org.openecard.crypto.tls.auth.DynamicAuthentication;
import java.io.IOException;
import org.openecard.bouncycastle.crypto.tls.PSKTlsClient;
import org.openecard.bouncycastle.crypto.tls.TlsAuthentication;
import org.openecard.bouncycastle.crypto.tls.TlsCipherFactory;
import org.openecard.bouncycastle.crypto.tls.TlsPSKIdentity;


/**
 * PSK TLS client also implementing the ClientCertTlsClient interface. <br/>
 * If not modified, the TlsAuthentication instance returned by {@link #getAuthentication()} is of type
 * {@link DynamicAuthentication} without further modifications.
 *
 * @author Tobias Wich <tobias.wich@ecsec.de>
 */
public class ClientCertPSKTlsClient extends PSKTlsClient implements ClientCertTlsClient {

    private final String fqdn;
    private TlsAuthentication tlsAuth;

    /**
     * Create a ClientCertPSKTlsClient for the given parameters.
     *
     * @param pskId PSK to use for this connection.
     * @param fqdn Fully qualified domain name of the server. This parameter is needed for SNI and for the creation
     * of the certificate verifier.
     */
    public ClientCertPSKTlsClient(TlsPSKIdentity pskId, String fqdn) {
	super(pskId, fqdn);
	this.fqdn = fqdn;
    }
    /**
     * Create a ClientCertPSKTlsClient for the given parameters.
     *
     * @param tcf Cipher factory to use in this client.
     * @param pskId PSK to use for this connection.
     * @param fqdn Fully qualified domain name of the server. This parameter is needed for SNI and for the creation
     * of the certificate verifier.
     */
    public ClientCertPSKTlsClient(TlsCipherFactory tcf, TlsPSKIdentity pskId, String fqdn) {
	super(tcf, pskId, fqdn);
	this.fqdn = fqdn;
    }


    @Override
    public synchronized TlsAuthentication getAuthentication() throws IOException {
	if (tlsAuth == null) {
	    DynamicAuthentication tlsAuthTmp = new DynamicAuthentication();
	    tlsAuthTmp.setHostname(fqdn);
	    tlsAuth = tlsAuthTmp;
	}
	return tlsAuth;
    }

    @Override
    public synchronized void setAuthentication(TlsAuthentication tlsAuth) {
	this.tlsAuth = tlsAuth;
    }

}
