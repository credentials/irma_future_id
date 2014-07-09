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

package org.openecard.crypto.tls.auth;

import java.io.IOException;
import java.util.List;
import javax.annotation.Nullable;
import org.openecard.bouncycastle.crypto.tls.Certificate;
import org.openecard.bouncycastle.crypto.tls.CertificateRequest;
import org.openecard.bouncycastle.crypto.tls.TlsAuthentication;
import org.openecard.bouncycastle.crypto.tls.TlsCredentials;
import org.openecard.crypto.tls.CertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Implementation of the TlsAuthentication interface for certificate verification.
 *
 * @author Tobias Wich <tobias.wich@ecsec.de>
 */
public class DynamicAuthentication implements TlsAuthentication {

    private static final Logger logger = LoggerFactory.getLogger(DynamicAuthentication.class);

    private String hostname;
    private CertificateVerifier certVerifier;
    private CredentialFactory credentialFactory;
    private Certificate lastCertChain;

    /**
     * Nullary constructor.
     * If no parameters are set later through setter functions, this instance will perform no server certificate checks
     * and return an empty client certificate list.
     */
    public DynamicAuthentication() {
    }

    /**
     * Create a new DynamicAuthentication using the given parameters. 
     * They can later be changed using the setter functions.
     * 
     * @param hostName Name of the host that will be used for certificate validation when a verifier is set.
     * @param certVerifier Verifier used for server certificate checks.
     * @param credentialFactory Factory that provides client credentials when they are requested from the server.
     */
    public DynamicAuthentication(@Nullable String hostName, @Nullable CertificateVerifier certVerifier,
	    @Nullable CredentialFactory credentialFactory) {
	this.hostname = hostName;
	this.certVerifier = certVerifier;
	this.credentialFactory = credentialFactory;
    }

    /**
     * Sets the host name for the certificate verification step.
     *
     * @see #notifyServerCertificate(org.openecard.bouncycastle.crypto.tls.Certificate)
     * @param hostname Name of the host that will be used for certificate validation, when a verifier is set.
     */
    public void setHostname(String hostname) {
	this.hostname = hostname;
    }

    /**
     * Sets the implementation for the certificate verification step.
     *
     * @see #notifyServerCertificate(org.openecard.bouncycastle.crypto.tls.Certificate)
     * @see CertificateVerifier
     * @param certVerifier Verifier to use for server certificate checks.
     */
    public void setCertificateVerifier(CertificateVerifier certVerifier) {
	this.certVerifier = certVerifier;
    }

    /**
     * Sets the factory which is used to find and create a credential reference for the authentication.
     *
     * @see #getClientCredentials(org.openecard.bouncycastle.crypto.tls.CertificateRequest)
     * @param credentialFactory Factory that provides client credentials when they are requested from the server.
     */
    public void setCredentialFactory(@Nullable CredentialFactory credentialFactory) {
	this.credentialFactory = credentialFactory;
    }


    /**
     * Verify the server certificate of the TLS handshake.
     * In case no implementation is set (via {@link #setCertificateVerifier(CertificateVerifier)}), no action is
     * performed.<br/>
     * The actual implementation is responsible for the types of verification that are performed. Besides the usual
     * hostname and certificate chain verification, those types could also include CRL and OCSP checking.
     *
     * @see CertificateVerifier
     * @param crtfct Certificate chain of the server as transmitted in the TLS handshake.
     * @throws IOException when certificate verification failed.
     */
    @Override
    public void notifyServerCertificate(Certificate crtfct) throws IOException {
	// save server certificate
	this.lastCertChain = crtfct;
	// try to validate
	if (certVerifier != null) {
	    // perform validation depending on the available parameters
	    if (hostname != null) {
		certVerifier.isValid(crtfct, hostname);
	    } else {
		logger.warn("Hostname not available for certificate verification.");
		certVerifier.isValid(crtfct);
	    }
	} else {
	    // no verifier available
	    logger.warn("No certificate verifier available, skipping certificate verification.");
	}
    }

    /**
     * Gets the client credentials based on the credential factory saved in this instance, or an empty credential.
     * From RFC 4346 sec. 7.4.6:
     * <p>If no suitable certificate is available, the client SHOULD send a certificate message containing no
     * certificates.</p>
     *
     * @param cr Certificate request as received in the TLS handshake.
     * @see CredentialFactory
     */
    @Override
    public TlsCredentials getClientCredentials(CertificateRequest cr) {
	if (credentialFactory != null) {
	    List<TlsCredentials> credentials = credentialFactory.getClientCredentials(cr);
	    if (! credentials.isEmpty()) {
		return credentials.get(0);
	    }
	}
	// fall back to no auth, when no credential is found
	return new TlsCredentials() {
	    @Override
	    public Certificate getCertificate() {
		return Certificate.EMPTY_CHAIN;
	    }
	};
    }

    /**
     * Returns the certificate chain which is processed during the TLS authentication.
     *
     * @return The certificate chain of the last certificate validation or null if none is available.
     */
    @Nullable
    public Certificate getServerCertificate() {
	return lastCertChain;
    }

}
