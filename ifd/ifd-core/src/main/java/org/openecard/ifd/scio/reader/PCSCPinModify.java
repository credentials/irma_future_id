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

package org.openecard.ifd.scio.reader;

import iso.std.iso_iec._24727.tech.schema.PasswordAttributesType;
import iso.std.iso_iec._24727.tech.schema.PasswordTypeType;
import java.io.ByteArrayOutputStream;
import org.openecard.common.USBLangID;
import org.openecard.common.util.ByteUtils;
import org.openecard.common.util.IntegerUtils;
import org.openecard.common.util.PINUtils;
import org.openecard.common.util.UtilException;
import org.openecard.ifd.scio.IFDException;


/**
 * @author Tobias Wich <tobias.wich@ecsec.de>
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 */
public class PCSCPinModify {

    private final PasswordTypeType pwdType;
    private final int minLen;
    private final int storedLen;
    private final int maxLen;

    public PCSCPinModify(PasswordAttributesType attributes, byte[] cmdTemplate) throws IFDException {
	this.pwdType = attributes.getPwdType();
	this.minLen = attributes.getMinLength().intValue();
	this.storedLen = attributes.getStoredLength().intValue();
	if (attributes.getMaxLength() != null) {
	    this.maxLen = attributes.getMaxLength().intValue();
	} else {
	    if (pwdType == PasswordTypeType.ISO_9564_1) {
		this.maxLen = (storedLen * 2) - 2;
	    } else if (pwdType == PasswordTypeType.BCD) {
		this.maxLen = storedLen * 2;
	    } else {
		this.maxLen = this.storedLen;
	    }
	}
	// initialise content needed for serialisation
	prepareStructure(attributes, cmdTemplate);
    }

    private void prepareStructure(PasswordAttributesType attributes, byte[] cmdTemplate) throws IFDException {
	// get apdu and pin template
	byte[] pinTemplate;

	try {
	    pinTemplate = PINUtils.createPinMask(attributes);
	} catch (UtilException e) {
	    IFDException ex = new IFDException(e);
	    throw ex;
	}

	byte[] template = cmdTemplate;
	if (pinTemplate.length > 0) {
	    template = ByteUtils.concatenate(cmdTemplate, (byte) pinTemplate.length);
	    template = ByteUtils.concatenate(template, pinTemplate);
	}
	setData(template);

	boolean nibbleHandling = pwdType == PasswordTypeType.BCD || pwdType == PasswordTypeType.ISO_9564_1;
	boolean isoPin = pwdType == PasswordTypeType.ISO_9564_1;
	int pinLenIdx = template.length; // pointer to byte containing pin length in iso encoding
	int pinPos = isoPin ? pinLenIdx + 1 : pinLenIdx;

	// prepare bmFormatString
	byte bmSysUnits = 1; // bytes
	byte bmPinPos = (byte) (isoPin ? 1 : 0);
	byte bmJustify = 0; // left
	byte bmPinType = 0; // binary
	if (nibbleHandling) {
	    bmPinType = 1;
	} else if (pwdType == PasswordTypeType.ASCII_NUMERIC) {
	    bmPinType = 2;
	}
	this.bmFormatString = (byte) ((bmSysUnits << 7) | (bmPinPos << 3) | (bmJustify << 2) | bmPinType);

	// prepare pin block string
	byte bmPinManagement = (byte) (isoPin ? 4 : 0); // number of bits of the length field
	byte pinSize = (byte) (isoPin ? storedLen - 1 : storedLen);
	this.bmPINBlockString = (byte) ((bmPinManagement << 4) | pinSize);

	// pin length format
	byte bmPinLengthUnit = 0; // bits
	byte bmPinBytePos = (byte) (isoPin ? 4 : 0);
	bmPINLengthFormat = (byte) ((bmPinLengthUnit << 4) | bmPinBytePos);

	setMinPINSize((byte) minLen);
	setMaxPINSize((byte) maxLen);
    }




    /** timeout in seconds, 0 means default */
    public byte bTimeOut = 0x15;
    /** timeout in seconds after first keystroke */
    public byte bTimeOut2 = 0x05;
    /** formatting options, USB_CCID_PIN_FORMAT */
    public byte bmFormatString = 0;
    /** bits 7-4 bit size of PIN length in APDU, bits 3-0 PIN block size in bytes after justification and formatting */
    public byte bmPINBlockString = 0;
    /** bits 7-5 RFU, bit 4 set if system units are bytes clear if system units are bits, bits 3-0 PIN length position in system units */
    public byte bmPINLengthFormat = 0;
    /** Insertion position offset in bytes for the current PIN */
    private byte bInsertionOffsetOld = 0x00;
    /** Insertion position offset in bytes for the new PIN */
    private byte bInsertionOffsetNew = 0x00;
    /** XXYY, where XX is minimum PIN size in digits, YY is maximum */
    private short wPINMaxExtraDigit = 0;
    /** Flags governing need for confirmation of new PIN */
    private byte bConfirmPIN = 0x01;
    /** Conditions under which PIN entry should be considered complete.
     * <p>The value is a bit wise OR operation:
     * <ul><li>0x1 Max size reached</li>
     *     <li>0x2 Validation key pressed</li>
     *     <li>0x4 Timeout occurred</li></ul></p> */
    private byte bEntryValidationCondition = 0x2;
    /** Number of messages to display for PIN verification management.
     * <p>The value is one of:
     * <ul><li>0x0 no string</li>
     *     <li>0x1 Message indicated by msg idx</li>
     *     <li>0xFF default CCID message</li></ul></p> */
    private byte bNumberMessage = (byte) 0x02;
    /** Language for messages */
    private short wLangId = USBLangID.German_Standard.getCode(); // this software is international, so use german of couse ;-)
    /** Message index (should be 00).
     * <p>The first three messages should be as follows in the reader:
     * <ul><li>0x0 PIN insertion prompt: "ENTER PIN"</li>
     *     <li>0x1 PIN modification prompt: "ENTER NEW PIN"</li>
     *     <li>0x2 New PIN confirmation prompt: "CONFIRM NEW PIN"</li></ul></p> */
    /** Index of 1st prompting message */
    private byte bMsgIndex1 = 0x00;
    /** Index of 2nd prompting message */
    private byte bMsgIndex2 = 0x01;
    /** Index of 3rd prompting message */
    private byte bMsgIndex3 = 0x02;
    /** T=1 I-block prologue field to use (fill with 00) */
    private final byte[] bTeoPrologue = new byte[] {0,0,0};
    /** length of Data to be sent to the ICC */
    private int ulDataLength = 0;
    /** Data to send to the ICC */
    private byte[] abData;


    public void setMinPINSize(byte minSize) {
	wPINMaxExtraDigit = (short) ((wPINMaxExtraDigit & 0x00FF) | (minSize << 8));
    }
    public byte getMinPINSize() {
	return (byte) ((wPINMaxExtraDigit >> 8) & 0xFF);
    }

    public void setMaxPINSize(byte maxSize) {
	wPINMaxExtraDigit = (short) ((wPINMaxExtraDigit & 0xFF00) | maxSize);
    }
    public byte getMaxPINSize() {
	return (byte) (wPINMaxExtraDigit & 0xFF);
    }

    public void setData(byte[] data) {
	if (data != null) {
	    ulDataLength = data.length;
	    abData = data;
	}
    }


    public byte[] toBytes() {
	ByteArrayOutputStream o = new ByteArrayOutputStream(42); // just a random magic number ^^
	// write all numbers to the stream
	o.write(bTimeOut);
	o.write(bTimeOut2);
	o.write(bmFormatString);
	o.write(bmPINBlockString);
	o.write(bmPINLengthFormat);
	o.write(bInsertionOffsetOld);
	o.write(bInsertionOffsetNew);
	o.write(getMaxPINSize());
	o.write(getMinPINSize());
	o.write(bConfirmPIN);
	o.write(bEntryValidationCondition);
	o.write(bNumberMessage);
	byte lang_low  = (byte) (wLangId & 0xFF);
	byte lang_high = (byte) ((wLangId >> 8) & 0xFF);
	o.write(lang_high);
	o.write(lang_low);
	o.write(bMsgIndex1);
	o.write(bMsgIndex2);
	o.write(bMsgIndex3);
	o.write(bTeoPrologue, 0, bTeoPrologue.length);
	byte[] ulDataLength_bytes = IntegerUtils.toByteArray(ulDataLength);
	for (int i = ulDataLength_bytes.length - 1; i >= 0; i--) {
	    o.write(ulDataLength_bytes[i]);
	}
	// write missing bytes to length field
	for (int i = ulDataLength_bytes.length; i < 4; i++) {
	    o.write(0);
	}
	if (ulDataLength > 0) {
	    o.write(abData, 0, abData.length);
	}

	byte[] result = o.toByteArray();
	return result;
    }

}
