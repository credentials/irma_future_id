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

package org.openecard.common.util;

import java.util.Comparator;


/**
 * Comparator class for byte arrays.
 * Makes it possible to use byte arrays as keys in sorted data structures.
 *
 * @author Tobias Wich <tobias.wich@ecsec.de>
 */
public class ByteComparator implements Comparator<byte[]> {

    @Override
    public int compare(byte[] o1, byte[] o2) {
	if (o1 == o2) {
	    return 0;
	}
	if (o1 == null) {
	    return -1;
	}
	if (o2 == null) {
	    return 1;
	}
	if (o1.length != o2.length) {
	    return o1.length - o2.length;
	}

	for (int i = 0; i < o1.length; i++) {
	    // use int so no overflow is possible
	    int b1 = o1[i];
	    int b2 = o2[i];
	    if (b1 != b2) {
		return b1 - b2;
	    }
	}

	// equal arrays
	return 0;
    }

}
