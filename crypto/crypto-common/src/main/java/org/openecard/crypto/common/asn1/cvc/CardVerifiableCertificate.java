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

package org.openecard.crypto.common.asn1.cvc;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.Iterator;
import java.util.List;
import org.openecard.common.tlv.TLV;
import org.openecard.common.tlv.TLVException;
import org.openecard.common.util.ByteUtils;


/**
 * Implements a Card Verifiable Certificate.
 *
 * See BSI-TR-03110, version 2.10, part 3, section C.
 *
 * @author Moritz Horsch <horsch@cdc.informatik.tu-darmstadt.de>
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 */
public class CardVerifiableCertificate {

    // Card Verifiable Certificate
    private static final int TAG_CVC = 0x7F21;
    // Certificate Body
    private static final int TAG_BODY = 0x7F4E;
    // Certificate Signature
    private static final int TAG_SIGNATURE = 0x5F37;
    // Certificate Profile Identifier (CPI)
    private static final int TAG_CPI = 0x5F29;
    // Certification Authority Reference (CAR)
    private static final int TAG_CAR = 0x42;
    // Public Key
    private static final int TAG_PUBLIC_KEY = 0x7F49;
    // Certificate Holder Reference (CHR)
    private static final int TAG_CHR = 0x5F20;
    // Certificate Holder Authorisation Template (CHAT)
    private static final int TAG_CHAT = 0x7F4C;
    // Certificate Effective Date
    private static final int TAG_EFFECTIVE_DATE = 0x5F25;
    // Certificate Expiration Date
    private static final int TAG_EXPIRATION_DATE = 0x5F24;
    // Certificate Extension
    private static final int TAG_EXTENSION = 0x65;
    // Certificate body
    private byte[] body;
    // Certificate signature
    private byte[] signature;
    // Certificate Profile Identifier (CPI)
    private byte[] cpi;
    // Certification Authority Reference (CAR)
    private PublicKeyReference car;
    // Certificate Holder Reference (CHR)
    private PublicKeyReference chr;
    // Public key
    private PublicKey publicKey;
    // Certificate Holder Authorization Template (CHAT)
    private CHAT chat;
    // Certificate Effective Date
    private Calendar effectiveDate;
    // Certificate Expiration Date
    private Calendar expirationDate;
    // Certificate Extension
    private byte[] extensions;
    // TLV encoded certificate
    private TLV certificate;

    /**
     * Create a new Card Verifiable Certificate.
     *
     * @param cvc CardVerifiableCertificate
     * @throws CertificateException
     * @throws TLVException
     */
    public CardVerifiableCertificate(byte[] cvc) throws CertificateException, TLVException {
	this(TLV.fromBER(cvc));
    }

    /**
     * Create a new Card Verifiable Certificate.
     *
     * @param cvc TLV encoded certificate
     * @throws CertificateException
     */
    public CardVerifiableCertificate(TLV cvc) throws CertificateException {
	try {
	    // TLV encoded body and signature
	    certificate = cvc;

	    // Certificate body
	    TLV bodyObject = cvc.findChildTags(TAG_BODY).get(0);
	    body = bodyObject.getValue();

	    // Certificate signature
	    TLV signatureObject = cvc.findChildTags(TAG_SIGNATURE).get(0);
	    signature = signatureObject.getValue();

	    // Certificate body elements
	    List<TLV> bodyElements = bodyObject.getChild().asList();

	    for (Iterator<TLV> it = bodyElements.iterator(); it.hasNext();) {
		TLV item = it.next();
		int itemTag = (int) item.getTagNumWithClass();

		switch (itemTag) {
		    case TAG_CPI:
			cpi = bodyObject.findChildTags(TAG_CPI).get(0).getValue();
			break;
		    case TAG_CAR:
			car = new PublicKeyReference(bodyObject.findChildTags(TAG_CAR).get(0).getValue());
			break;
		    case TAG_PUBLIC_KEY:
			publicKey = PublicKey.getInstance(bodyObject.findChildTags(TAG_PUBLIC_KEY).get(0));
			break;
		    case TAG_CHR:
			chr = new PublicKeyReference(bodyObject.findChildTags(TAG_CHR).get(0).getValue());
			break;
		    case TAG_CHAT:
			chat = new CHAT(bodyObject.findChildTags(TAG_CHAT).get(0));
			break;
		    case TAG_EFFECTIVE_DATE:
			TLV effectiveDateObject = bodyObject.findChildTags(TAG_EFFECTIVE_DATE).get(0);
			effectiveDate = parseDate(effectiveDateObject.getValue());
			break;
		    case TAG_EXPIRATION_DATE:
			TLV expirationDateObject = bodyObject.findChildTags(TAG_EXPIRATION_DATE).get(0);
			expirationDate = parseDate(expirationDateObject.getValue());
			break;
		    case TAG_EXTENSION:
			extensions = bodyObject.findChildTags(TAG_EXTENSION).get(0).getValue();
			break;
		    default:
			break;
		}
	    }
	    verify();
	} catch (Exception e) {
	    throw new CertificateEncodingException("Malformed CardVerifiableCertificates: " + e.getMessage());
	}
    }

    /**
     * See See BSI-TR-03110, version 2.10, part 3, section C.
     */
    private void verify() throws CertificateEncodingException {
	if (body == null || cpi == null || car == null
		|| publicKey == null || chr == null
		|| chat == null || effectiveDate == null
		|| expirationDate == null || signature == null) {
	    throw new CertificateEncodingException("Malformed CardVerifiableCertificates");
	}
    }

    /*
     * Parses the date.
     * Format YYMMDD (6 Bytes). Note: Januar = 0 not 1!
     */
    private Calendar parseDate(byte[] date) {
	Calendar cal = Calendar.getInstance();

	cal.set(Calendar.YEAR, 2000 + (date[0] * 10) + date[1]);
	cal.set(Calendar.MONTH, (date[2] * 10) + date[3] - 1);
	cal.set(Calendar.DATE, (date[4] * 10) + date[5]);

	return cal;
    }

    /**
     * Returns the body of the certificate.
     *
     * @return Body
     */
    public byte[] getBody() {
	return body;
    }

    /**
     * Returns the signature of the certificate.
     *
     * @return Signature
     */
    public byte[] getSignature() {
	return signature;
    }

    /**
     * Returns the Certificate Holder Authorization Template (CHAT).
     *
     * @return CHAT
     */
    public CHAT getCHAT() {
	return chat;
    }

    /**
     * Returns the Certificate Holder Reference (CHR).
     *
     * @return CHR
     */
    public PublicKeyReference getCHR() {
	return chr;
    }

    /**
     * Returns the Certification Authority Reference (CAR).
     *
     * @return CAR
     */
    public PublicKeyReference getCAR() {
	return car;
    }

    /**
     * Returns the public key.
     *
     * @return Public key
     */
    public PublicKey getPublicKey() {
	return publicKey;
    }

    /**
     * Returns the Certificate Profile Identifier (CPI).
     *
     * @return CPI
     */
    public byte[] getCPI() {
	return cpi;
    }

    /**
     * Returns the effective date of the certificate.
     *
     * @return Effective date
     */
    public Calendar getEffectiveDate() {
	return effectiveDate;
    }

    /**
     * Returns the expiration date of the certificate.
     *
     * @return Expiration date
     */
    public Calendar getExpirationDate() {
	return expirationDate;
    }

    /**
     * Returns the certificate extensions.
     *
     * @return Extensions
     */
    public byte[] getExtensions() {
	return extensions;
    }

    /**
     * Returns the certificate.
     *
     * @return Certificate
     */
    public TLV getCertificate() {
	return certificate;
    }

    /**
     * Compares the certificate.
     *
     * @param certificate Certificate
     * @return True if the certificate is equal
     */
    public boolean compare(CardVerifiableCertificate certificate) {
	return ByteUtils.compare(getSignature(), certificate.getSignature());
    }

}
