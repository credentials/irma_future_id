/**
 * IdemixLogEntry.java
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 * 
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, March 2013.
 */

package org.openecard.plugins.abcplugin;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Date;

/**
 * Low-level interface to the logs stored on the IRMA-card.
 *
 */
public class IdemixLogEntry {
	public enum Action {
		ISSUE,
		VERIFY,
		REMOVE,
		NONE
	}

	private Date timestamp;
	private Action action;
	private short credential;
	private byte[] terminal;

	/** Only one of these is set simultaneously */
	private short disclose;
	private byte[] data;

	/**
	 * Structure of log entry:
	 *  timestamp: 4 bytes
	 *  terminal: 4 bytes
	 *  action: 1 byte
	 *  credential: 2 bytes (short)
	 *  details: 5 bytes
	 *     selection: 2 bytes (left aligned, short)
	 *     data: 5 bytes
	 */

	private static final int IDX_TIMESTAMP = 0;
	private static final int SIZE_TIMESTAMP = 4;

	private static final int IDX_TERMINAL = 4;
	private static final int SIZE_TERMINAL = 4;

	private static final int IDX_ACTION = 8;

	private static final int IDX_CREDENTIAL = 9;

	private static final int IDX_SELECTION = 11;

	private static final int IDX_DETAILS = 11;
	private static final int SIZE_DETAILS = 5;

	private static final byte ACTION_NONE = 0x00;
	private static final byte ACTION_ISSUE = 0x01;
	private static final byte ACTION_PROVE = 0x02;
	private static final byte ACTION_REMOVE = 0x03;

	public IdemixLogEntry(byte[] log) {
		switch (log[IDX_ACTION]) {
		case ACTION_ISSUE:
			action = Action.ISSUE;
			data = Arrays.copyOfRange(log, IDX_DETAILS, IDX_DETAILS
					+ SIZE_DETAILS);
			disclose = 0;
			break;
		case ACTION_PROVE:
			action = Action.VERIFY;
			disclose = getShortAt(log, IDX_SELECTION);
			break;
		case ACTION_REMOVE:
			action = Action.REMOVE;
			break;
		case ACTION_NONE:
			action = Action.NONE;
		}

		terminal = Arrays.copyOfRange(log, IDX_TERMINAL, IDX_TERMINAL + SIZE_TERMINAL);

		credential = getShortAt(log, IDX_CREDENTIAL);

		BigInteger bitimestamp = new BigInteger(Arrays.copyOfRange(log, IDX_TIMESTAMP, SIZE_TIMESTAMP));
		timestamp = new Date(bitimestamp.longValue() * 1000);
	}
	
	public Date getTimestamp() {
		return timestamp;
	}

	public Action getAction() {
		return action;
	}

	public short getCredential() {
		return credential;
	}

	public byte[] getTerminal() {
		return terminal;
	}

	public short getDisclose() {
		return disclose;
	}

	public byte[] getData() {
		return data;
	}

	private static short getShortAt(byte[] array, int idx) {
		return (short) ((array[idx] << 8) + (array[idx + 1] & 0xff));
	}
	
	public String print() {
		switch(action) {
		case VERIFY:
			return ("VERIFICATION\n" + "\tTimestamp: " + timestamp.getTime() + "\n\tCredential: " + credential);
		case ISSUE:
			return ("ISSUANCE\n" + "\tTimestamp: " + timestamp.getTime() + "\n\tCredential: " + credential);
		case REMOVE:
			return ("REMOVE\n" + "\tTimestamp: " + timestamp.getTime() + "\n\tCredential: " + credential);
		case NONE:
			return ("Empty\n");
		}

		return null;
	}
}
