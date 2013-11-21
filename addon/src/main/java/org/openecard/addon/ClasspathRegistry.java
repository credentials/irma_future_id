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

package org.openecard.addon;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import org.openecard.addon.manifest.AddonSpecification;
import org.openecard.addon.manifest.AppExtensionSpecification;
import org.openecard.addon.manifest.AppPluginSpecification;
import org.openecard.addon.manifest.LocalizedString;
import org.openecard.addon.manifest.ProtocolPluginSpecification;
import org.openecard.common.util.FileUtils;
import org.openecard.ws.marshal.WSMarshaller;
import org.openecard.ws.marshal.WSMarshallerException;
import org.openecard.ws.marshal.WSMarshallerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;


/**
 * Addon registry serving add-ons from the classpath of the base app.
 * This type of registry works for JNLP and integrated plugins.
 *
 * @author Tobias Wich <tobias.wich@ecsec.de>
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 */
public class ClasspathRegistry implements AddonRegistry {

    private static final Logger logger = LoggerFactory.getLogger(ClasspathRegistry.class);

    private final ArrayList<AddonSpecification> registeredAddons = new ArrayList<AddonSpecification>();


    public ClasspathRegistry() throws WSMarshallerException {
	WSMarshaller marshaller = WSMarshallerFactory.createInstance();
	marshaller.addXmlTypeClass(AddonSpecification.class);
	
	loadManifest(marshaller, "IRMA Pin", "IRMApin-Plugin-Manifest.xml");
	loadManifest(marshaller, "IRMA Log", "IRMAlog-Plugin-Manifest.xml");
	loadManifest(marshaller, "IRMA Status", "IRMAstatus-Plugin-Manifest.xml");
	loadManifest(marshaller, "IRMA Credential", "IRMAcredential-Plugin-Manifest.xml");
	loadManifest(marshaller, "IRMA Prover", "IRMAprover-Plugin-Manifest.xml");
	loadManifest(marshaller, "TR-03112", "TCToken-Manifest.xml");
	loadManifest(marshaller, "PIN-Management", "PIN-Plugin-Manifest.xml");
	loadManifest(marshaller, "GenericCrypto", "GenericCrypto-Plugin-Manifest.xml");
	loadManifest(marshaller, "Status", "Status-Plugin-Manifest.xml");
	loadManifest(marshaller, "PKCS#11", "PKCS11-Manifest.xml");
    }

    private void loadManifest(WSMarshaller marshaller, String addonName, String fileName) {
	try {
	    InputStream manifestStream = FileUtils.resolveResourceAsStream(ClasspathRegistry.class, fileName);
	    if (manifestStream == null) {
		logger.warn("Skipped loading internal add-on {}, because it is not available.", addonName);
		return;
	    }
	    Document manifestDoc = marshaller.str2doc(manifestStream);
	    register((AddonSpecification) marshaller.unmarshal(manifestDoc));
	    logger.info("Loaded internal {} add-on.", addonName);
	} catch (IOException ex) {
	    logger.warn(String.format("Failed to load internal %s add-on.", addonName), ex);
	} catch (SAXException ex) {
	    logger.warn(String.format("Failed to load internal %s add-on.", addonName), ex);
	} catch (WSMarshallerException ex) {
	    logger.warn(String.format("Failed to load internal %s add-on.", addonName), ex);
	}
    }

    public final void register(AddonSpecification desc) {
	registeredAddons.add(desc);
    }

    @Override
    public Set<AddonSpecification> listAddons() {
	Set<AddonSpecification> list = new HashSet<AddonSpecification>();
	list.addAll(registeredAddons);
	return list;
    }

    @Override
    public AddonSpecification search(String id) {
	for (AddonSpecification desc : registeredAddons) {
	    if (desc.getId().equals(id)) {
		return desc;
	    }
	}
	return null;
    }

    @Override
    public Set<AddonSpecification> searchByName(String name) {
	Set<AddonSpecification> matchingAddons = new HashSet<AddonSpecification>();
	for (AddonSpecification desc : registeredAddons) {
	    for (LocalizedString s : desc.getLocalizedName()) {
		if (s.getValue().equals(name)) {
		    matchingAddons.add(desc);
		}
	    }
	}
	return matchingAddons;
    }

    @Override
    public Set<AddonSpecification> searchIFDProtocol(String uri) {
	Set<AddonSpecification> matchingAddons = new HashSet<AddonSpecification>();
	for (AddonSpecification desc : registeredAddons) {
	    ProtocolPluginSpecification protocolDesc = desc.searchIFDActionByURI(uri);
	    if (protocolDesc != null) {
		matchingAddons.add(desc);
	    }
	}
	return matchingAddons;
    }

    @Override
    public Set<AddonSpecification> searchSALProtocol(String uri) {
	Set<AddonSpecification> matchingAddons = new HashSet<AddonSpecification>();
	for (AddonSpecification desc : registeredAddons) {
	    ProtocolPluginSpecification protocolDesc = desc.searchSALActionByURI(uri);
	    if (protocolDesc != null) {
		matchingAddons.add(desc);
	    }
	}
	return matchingAddons;
    }

    @Override
    public ClassLoader downloadAddon(AddonSpecification addonSpec) {
	// TODO use other own classloader impl with security features
	return this.getClass().getClassLoader();
    }

    @Override
    public Set<AddonSpecification> searchByResourceName(String resourceName) {
	Set<AddonSpecification> matchingAddons = new HashSet<AddonSpecification>();
	for (AddonSpecification desc : registeredAddons) {
	    AppPluginSpecification actionDesc = desc.searchByResourceName(resourceName);
	    if (actionDesc != null) {
		matchingAddons.add(desc);
	    }
	}
	return matchingAddons;
    }

    @Override
    public Set<AddonSpecification> searchByActionId(String actionId) {
	Set<AddonSpecification> matchingAddons = new HashSet<AddonSpecification>();
	for (AddonSpecification desc : registeredAddons) {
	    AppExtensionSpecification actionDesc = desc.searchByActionId(actionId);
	    if (actionDesc != null) {
		matchingAddons.add(desc);
	    }
	}
	return matchingAddons;
    }

}
