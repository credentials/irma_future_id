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

package org.openecard.common.util;


/**
 * Parameterized pair class.
 * This simple immutable pair (or tuple) can hold arbitrary values, whose types must be specified by generics.
 *
 * @author Tobias Wich <tobias.wich@ecsec.de>
 */
public class Pair <P1, P2> {

    public final P1 p1;
    public final P2 p2;

    /**
     * Creates a Pair instance for the given parameters.
     *
     * @param p1 First value which is later accessible as {@code p1}.
     * @param p2 Second value which is later accessible as {@code p2}.
     */
    public Pair(P1 p1, P2 p2) {
	this.p1 = p1;
	this.p2 = p2;
    }

}
