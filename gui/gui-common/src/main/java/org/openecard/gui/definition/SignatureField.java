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

import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Definition class for signature fields.
 * Signature fields provide a drawing canvas where the user can create a signature.
 *
 * @author Tobias Wich <tobias.wich@ecsec.de>
 */
public final class SignatureField extends IDTrait implements InputInfoUnit, OutputInfoUnit {

    private static final Logger _logger = LoggerFactory.getLogger(SignatureField.class);

    private String text;
    private byte[] value;

    /**
     * Creates a new SignatureField instance and initializes it with the given ID.
     *
     * @param id The ID to initialize the instance with.
     */
    public SignatureField(String id) {
	super(id);
    }


    /**
     * Gets the description text of the signature field.
     * The description text is shown besides the signature field.
     *
     * @return The description text of this element.
     */
    public String getText() {
	return text;
    }
    /**
     * Sets the description text of the signature field.
     * The description text is shown besides the signature field.
     *
     * @param text The description text of this element.
     */
    public void setText(String text) {
	this.text = text;
    }

    /**
     * Gets the value of the signature field.
     * The signature is an image. The value of the signature field is encoded as a PNG image.
     *
     * @return The value of the signature field encoded as a PNG image.
     */
    public byte[] getValue() {
	return (value == null) ? null : Arrays.copyOf(value, value.length);
    }

    /**
     * Sets the value of the signature field.
     * The signature is an image. The value of the signature field is encoded as a PNG image.
     *
     * @param value The value of the signature field encoded as a PNG image.
     */
    public void setValue(byte[] value) {
	this.value = Arrays.copyOf(value, value.length);
    }


    @Override
    public InfoUnitElementType type() {
	return InfoUnitElementType.SIGNAUTRE_FIELD;
    }


    @Override
    public void copyContentFrom(InfoUnit origin) {
	if (!(this.getClass().equals(origin.getClass()))) {
	    _logger.warn("Trying to copy content from type {} to type {}.", origin.getClass(), this.getClass());
	    return;
	}
	SignatureField other = (SignatureField) origin;
	// do copy
	this.text = other.text;
	if (other.value != null) {
	    this.value = Arrays.copyOf(other.value, other.value.length);
	}
    }

}
