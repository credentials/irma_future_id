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

package org.openecard.ifd.protocol.pace;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.openecard.bouncycastle.crypto.engines.AESFastEngine;
import org.openecard.bouncycastle.crypto.macs.CMac;
import org.openecard.bouncycastle.crypto.params.KeyParameter;
import org.openecard.common.apdu.common.CardCommandAPDU;
import org.openecard.common.tlv.TLV;
import org.openecard.common.util.ByteUtils;


/**
 * Implements Secure Messaging according to ISO/IEC 7816-4.
 *
 * @author Moritz Horsch <horsch@cdc.informatik.tu-darmstadt.de>
 */
public class SecureMessaging {

    private static final byte[] NULL = new byte[]{0x00};
    // ISO/IEC 7816-4 padding tag
    private static final byte PAD = (byte) 0x80;
    // Send Sequence Counter. See BSI-TR-03110 section F.3.
    private byte[] secureMessagingSSC;
    // Keys for encryption and message authentication.
    private byte[] keyMAC, keyENC;

    /**
     * Instantiates a new secure messaging.
     *
     * @param keyMAC Key for message authentication
     * @param keyENC Key for encryption
     */
    public SecureMessaging(byte[] keyMAC, byte[] keyENC) {
	this.keyENC = keyENC;
	this.keyMAC = keyMAC;

	secureMessagingSSC = new byte[16];
    }

    /**
     * Encrypt the APDU.
     *
     * @param apdu APDU
     * @return Encrypted APDU
     * @throws Exception
     */
    public byte[] encrypt(byte[] apdu) throws Exception {
	incrementSSC(secureMessagingSSC);
	byte[] commandAPDU = encrypt(apdu, secureMessagingSSC);
	incrementSSC(secureMessagingSSC);

	return commandAPDU;
    }

    /**
     * Encrypt the APDU.
     *
     * @param apdu APDU
     * @param secureMessagingSSC Secure Messaging Send Sequence Counter
     * @return Encrypted APDU
     * @throws Exception
     */
    private byte[] encrypt(byte[] apdu, byte[] secureMessagingSSC) throws Exception {
	ByteArrayOutputStream baos = new ByteArrayOutputStream();
	CardCommandAPDU cAPDU = new CardCommandAPDU(apdu);

	if (cAPDU.isSecureMessaging()) {
	    throw new IllegalArgumentException("Malformed APDU.");
	}

	byte[] data = cAPDU.getData();
	byte[] header = cAPDU.getHeader();
	int lc = cAPDU.getLC();
	int le = cAPDU.getLE();

	if (data != null) {
	    data = pad(data, 16);

	    // Encrypt data
	    Cipher c = getCipher(secureMessagingSSC, Cipher.ENCRYPT_MODE);
	    byte[] dataEncrypted = c.doFinal(data);

	    // Add padding indicator 0x01
	    dataEncrypted = ByteUtils.concatenate((byte) 0x01, dataEncrypted);

	    TLV dataObject = new TLV();
	    dataObject.setTagNumWithClass((byte) 0x87);
	    dataObject.setValue(dataEncrypted);
	    baos.write(dataObject.toBER());
	}

	// Write protected LE
	if (le >= 0) {
	    TLV leObject = new TLV();
	    leObject.setTagNumWithClass((byte) 0x97);
	    if (le == 0x100) {
		leObject.setValue(NULL);
	    } else if (le > 0x100) {
		leObject.setValue(new byte[]{(byte) ((le >> 8) & 0xFF), (byte) (le & 0xFF)});
	    } else {
		leObject.setValue(new byte[]{(byte) le});
	    }
	    baos.write(leObject.toBER());
	}

	// Indicate Secure Messaging
	// note: must be done before mac calculation
	header[0] |= 0x0C;

	/*
	 * Calculate MAC
	 */
	byte[] mac = new byte[16];
	CMac cmac = getCMAC(secureMessagingSSC);

	byte[] paddedHeader = pad(header, 16);
	cmac.update(paddedHeader, 0, paddedHeader.length);

	if (baos.size() > 0) {
	    byte[] paddedData = pad(baos.toByteArray(), 16);
	    cmac.update(paddedData, 0, paddedData.length);

	    lc = baos.size();
	}

	cmac.doFinal(mac, 0);
	mac = ByteUtils.copy(mac, 0, 8);

	//
	// Build APDU
	ByteArrayOutputStream out = new ByteArrayOutputStream();

	// Write header
	out.write(header);

	// Add MAC length to LC
	lc += 10;

	// Write LC field
	if ((lc > 0xFF) || (le > 0x100)) {
	    out.write(NULL);
	    out.write((lc >> 8) & 0xFF);
	    out.write(lc & 0xFF);
	} else {
	    out.write(lc & 0xFF);
	}

	// Write data if present
	if (baos.size() > 0) {
	    out.write(baos.toByteArray());
	}
	// Write SM tag
	out.write(new byte[]{(byte) 0x8E, (byte) 0x08});

	// Write SM MAC
	out.write(mac);
	out.write(NULL);

	if ((lc > 0xFF) || (le > 0x100)) {
	    out.write(NULL);
	}

	return out.toByteArray();
    }

    /**
     * Decrypt the APDU.
     *
     * @param response the response
     * @return the byte[]
     * @throws Exception the exception
     */
    public byte[] decrypt(byte[] response) throws Exception {
	if (response.length < 12) {
	    throw new IllegalArgumentException("Malformed Secure Messaging APDU");
	}
	return decrypt(response, secureMessagingSSC);
    }

    /**
     * Decrypt the APDU.
     *
     * @param response the response
     * @param secureMessagingSSC the secure messaging ssc
     * @return the byte[]
     * @throws Exception the exception
     */
    private byte[] decrypt(byte[] response, byte[] secureMessagingSSC) throws Exception {
	ByteArrayInputStream bais = new ByteArrayInputStream(response);
	ByteArrayOutputStream baos = new ByteArrayOutputStream(response.length - 10);

	// Status bytes of the response APDU. MUST be 2 bytes.
	byte[] statusBytes = new byte[2];
	// Padding-content indicator followed by cryptogram 0x87.
	byte[] dataObject = null;
	// Cryptographic checksum 0x8E. MUST be 8 bytes.
	byte[] macObject = new byte[8];

	/*
	 * Read APDU structure
	 * Case 1: DO99|DO8E|SW1SW2
	 * Case 2: DO87|DO99|DO8E|SW1SW2
	 * Case 3: DO99|DO8E|SW1SW2
	 * Case 4: DO87|DO99|DO8E|SW1SW2
	 */
	byte tag = (byte) bais.read();

	// Read data object (OPTIONAL)
	if (tag == (byte) 0x87) {
	    int size = bais.read();
	    if (size > 0x80) {
		byte[] sizeBytes = new byte[size & 0x0F];
		bais.read(sizeBytes, 0, sizeBytes.length);
		size = new BigInteger(1, sizeBytes).intValue();
	    }
	    bais.skip(1); // Skip encryption header
	    dataObject = new byte[size - 1];
	    bais.read(dataObject, 0, dataObject.length);

	    tag = (byte) bais.read();
	}

	// Read processing status (REQUIRED)
	if (tag == (byte) 0x99) {
	    if (bais.read() == (byte) 0x02) {
		bais.read(statusBytes, 0, 2);
		tag = (byte) bais.read();
	    }
	} else {
	    throw new IOException("Malformed Secure Messaging APDU");
	}

	// Read MAC (REQUIRED)
	if (tag == (byte) 0x8E) {
	    if (bais.read() == (byte) 0x08) {
		bais.read(macObject, 0, 8);
	    }
	} else {
	    throw new IOException("Malformed Secure Messaging APDU");
	}

	// Only 2 bytes status should remain
	if (bais.available() != 2) {
	    throw new IOException("Malformed Secure Messaging APDU");
	}

	// Calculate MAC for verification
	CMac cmac = getCMAC(secureMessagingSSC);
	byte[] mac = new byte[16];

	synchronized (cmac) {
	    ByteArrayOutputStream macData = new ByteArrayOutputStream();

	    // Write padding-content
	    if (dataObject != null) {
		TLV paddedDataObject = new TLV();
		paddedDataObject.setTagNumWithClass((byte) 0x87);
		paddedDataObject.setValue(ByteUtils.concatenate((byte) 0x01, dataObject));
		macData.write(paddedDataObject.toBER());
	    }
	    // Write status bytes
	    TLV statusBytesObject = new TLV();
	    statusBytesObject.setTagNumWithClass((byte) 0x99);
	    statusBytesObject.setValue(statusBytes);
	    macData.write(statusBytesObject.toBER());

	    byte[] paddedData = pad(macData.toByteArray(), 16);
	    cmac.update(paddedData, 0, paddedData.length);

	    cmac.doFinal(mac, 0);
	    mac = ByteUtils.copy(mac, 0, 8);
	}

	// Verify MAC
	if (!ByteUtils.compare(mac, macObject)) {
	    throw new GeneralSecurityException("Secure Messaging MAC verification failed");
	}

	// Decrypt data
	if (dataObject != null) {
	    Cipher c = getCipher(secureMessagingSSC, Cipher.DECRYPT_MODE);
	    byte[] data_decrypted = c.doFinal(dataObject);
	    baos.write(unpad(data_decrypted));
	}

	// Add status code
	baos.write(statusBytes);

	return baos.toByteArray();
    }

    /**
     * Increment the Send Sequence Counter (SSC).
     *
     * @param ssc the Send Sequence Counter (SSC)
     */
    public static void incrementSSC(byte[] ssc) {
	for (int i = ssc.length - 1; i >= 0; i--) {
	    ssc[i]++;
	    if (ssc[i] != 0) {
		break;
	    }
	}
    }

    /*
     * Cipher functions
     */
    /**
     * Gets the cipher for de/encryption.
     *
     * @param smssc the Secure Messaging Send Sequence Counter
     * @param mode the mode indicating de/encryption
     * @return the cipher
     * @throws Exception the exception
     */
    private Cipher getCipher(byte[] smssc, int mode) throws Exception {
	Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
	Key key = new SecretKeySpec(keyENC, "AES");
	byte[] iv = getCipherIV(smssc);
	AlgorithmParameterSpec algoPara = new IvParameterSpec(iv);

	c.init(mode, key, algoPara);

	return c;
    }

    /**
     * Gets the Initialization Vector (IV) for the cipher.
     *
     * @param smssc Secure Messaging Send Sequence Counter
     * @return Initialization Vector
     * @throws Exception
     */
    private byte[] getCipherIV(byte[] smssc) throws Exception {
	Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
	Key key = new SecretKeySpec(keyENC, "AES");

	c.init(Cipher.ENCRYPT_MODE, key);

	return c.doFinal(smssc);
    }

    /**
     * Gets the CMAC.
     *
     * @param smssc Secure Messaging Send Sequence Counter
     * @return CMAC
     */
    private CMac getCMAC(byte[] smssc) {
	CMac cmac = new CMac(new AESFastEngine());
	cmac.init(new KeyParameter(keyMAC));
	cmac.update(smssc, 0, smssc.length);

	return cmac;
    }

    /*
     * ISO/IEC 7816-4 padding functions
     */
    /**
     * Padding the data.
     *
     * @param data Unpadded data
     * @param blockSize Block size
     * @return Padded data
     */
    private byte[] pad(byte[] data, int blockSize) {
	byte[] result = new byte[data.length + (blockSize - data.length % blockSize)];
	System.arraycopy(data, 0, result, 0, data.length);
	result[data.length] = PAD;

	return result;
    }

    /**
     * Unpadding the data.
     *
     * @param data Padded data
     * @return Unpadded data
     */
    private byte[] unpad(byte[] data) {
	for (int i = data.length - 1; i >= 0; i--) {
	    if (data[i] == PAD) {
		return ByteUtils.copy(data, 0, i);
	    }
	}

	return data;
    }

}
