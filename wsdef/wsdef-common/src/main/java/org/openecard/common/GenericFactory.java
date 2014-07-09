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

package org.openecard.common;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.util.Properties;


/**
 * Generic factory capable of creating instances for a type defined in a config file.
 * The config file must be present in Java properties form an the key naming the class of the type that is to be created
 * must be known.
 *
 * @param <T> Type the factory creates instances for.
 *
 * @author Tobias Wich <tobias.wich@ecsec.de>
 */
public class GenericFactory <T> {

    private final Constructor<T> constructor;

    public GenericFactory(Properties properties, String key) throws GenericFactoryException {
	final String className = properties.getProperty(key);
	if (className == null) {
	    throw new GenericFactoryException("No factory class defined for the specified key '" + key + "'.");
	}

	try {
	    constructor = loadClass(className);
	} catch (ClassNotFoundException ex) {
	    throw new GenericFactoryException(ex);
	} catch (NoSuchMethodException ex) {
	    throw new GenericFactoryException(ex);
	}
    }


    public T getInstance() throws GenericFactoryException {
	try {
	    T o = constructor.newInstance(); // null because it is static
	    return o; // type is asserted by method definition
	} catch (InstantiationException ex) {
	    throw new GenericFactoryException(ex);
	} catch (IllegalAccessException ex) {
	    throw new GenericFactoryException(ex);
	} catch (IllegalArgumentException ex) {
	    throw new GenericFactoryException(ex);
	} catch (InvocationTargetException ex) {
	    throw new GenericFactoryException(ex);
	}
    }


    private Constructor<T> loadClass(String className) throws ClassNotFoundException, GenericFactoryException, NoSuchMethodException {
	ClassLoader cl = this.getClass().getClassLoader();
	Class<?> c = cl.loadClass(className);
	Constructor<T> m = (Constructor<T>) c.getConstructor();
	if (Modifier.isPublic(m.getModifiers())) {
	    return m;
	} else {
	    throw new GenericFactoryException("Constructor of class " + className + " is not publicly available.");
	}
    }

}
