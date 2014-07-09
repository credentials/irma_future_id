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

package org.openecard.gui.definition;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Definition class for simple text elements.
 * The Text element is a text displaying an information to the user.
 *
 * @author Tobias Wich <tobias.wich@ecsec.de>
 */
public final class Text extends IDTrait implements InputInfoUnit {

    private static final Logger _logger = LoggerFactory.getLogger(Text.class);

    private String text;


    /**
     * Gets the text set for this instance.
     *
     * @return The text of this instance.
     */
    public String getText() {
	return text;
    }
    /**
     * Sets the text for this instance.
     *
     * @param text The text to set for this instance.
     */
    public void setText(String text) {
	this.text = text;
    }


    @Override
    public InfoUnitElementType type() {
	return InfoUnitElementType.TEXT;
    }


    @Override
    public void copyContentFrom(InfoUnit origin) {
	if (!(this.getClass().equals(origin.getClass()))) {
	    _logger.warn("Trying to copy content from type {} to type {}.", origin.getClass(), this.getClass());
	    return;
	}
	Text other = (Text) origin;
	// do copy
	this.text = other.text;
    }

}
