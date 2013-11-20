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

package org.openecard.sal.protocol.irmalog;

import iso.std.iso_iec._24727.tech.schema.CardApplicationConnect;
import iso.std.iso_iec._24727.tech.schema.CardApplicationConnectResponse;
import iso.std.iso_iec._24727.tech.schema.CardApplicationPath;
import iso.std.iso_iec._24727.tech.schema.CardApplicationPathResponse;
import iso.std.iso_iec._24727.tech.schema.CardApplicationPathType;
import iso.std.iso_iec._24727.tech.schema.Connect;
import iso.std.iso_iec._24727.tech.schema.ConnectResponse;
import iso.std.iso_iec._24727.tech.schema.ConnectionHandleType;
import iso.std.iso_iec._24727.tech.schema.ConnectionHandleType.RecognitionInfo;
import iso.std.iso_iec._24727.tech.schema.DIDAuthenticate;
import iso.std.iso_iec._24727.tech.schema.DIDAuthenticateResponse;
import iso.std.iso_iec._24727.tech.schema.DIDAuthenticationDataType;
import iso.std.iso_iec._24727.tech.schema.DIDGet;
import iso.std.iso_iec._24727.tech.schema.DIDGetResponse;
import iso.std.iso_iec._24727.tech.schema.DIDScopeType;
import iso.std.iso_iec._24727.tech.schema.DIDUpdate;
import iso.std.iso_iec._24727.tech.schema.DIDUpdateDataType;
import iso.std.iso_iec._24727.tech.schema.DIDUpdateResponse;
import iso.std.iso_iec._24727.tech.schema.Encipher;
import iso.std.iso_iec._24727.tech.schema.EncipherResponse;
import iso.std.iso_iec._24727.tech.schema.EstablishContext;
import iso.std.iso_iec._24727.tech.schema.EstablishContextResponse;
import iso.std.iso_iec._24727.tech.schema.ListIFDs;
import iso.std.iso_iec._24727.tech.schema.ListIFDsResponse;
import iso.std.iso_iec._24727.tech.schema.PinCompareMarkerType;
import java.math.BigInteger;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.openecard.addon.AddonManager;
import org.openecard.bouncycastle.util.encoders.Hex;
import org.openecard.common.ClientEnv;
import org.openecard.common.ECardConstants;
import org.openecard.common.enums.EventType;
import org.openecard.common.interfaces.Dispatcher;
import org.openecard.common.sal.anytype.IRMALOGMarkerType;
import org.openecard.common.sal.state.CardStateMap;
import org.openecard.common.sal.state.SALStateCallback;
import org.openecard.common.util.ByteUtils;
import org.openecard.common.util.StringUtils;
import org.openecard.event.EventManager;
import org.openecard.gui.UserConsent;
import org.openecard.gui.swing.SwingDialogWrapper;
import org.openecard.gui.swing.SwingUserConsent;
import org.openecard.ifd.scio.IFD;
import org.openecard.recognition.CardRecognition;
import org.openecard.sal.TinySAL;
import org.openecard.transport.dispatcher.MessageDispatcher;
import org.testng.SkipException;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import static org.testng.Assert.*;

import org.irmacard.idemix.util.IdemixLogEntry;

/**
 *
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 */
public class IRMALOGProtocolTest {

    private static ClientEnv env;
    private static TinySAL instance;
    private static CardStateMap states;
    private static EventManager em;

    byte[] appIdentifier_IRMA = Hex.decode("F849524D4163617264");

    @BeforeClass
    public static void setUp() throws Exception {
	env = new ClientEnv();
	Dispatcher d = new MessageDispatcher(env);
	env.setDispatcher(d);
	IFD ifd = new IFD();
	ifd.setGUI(new SwingUserConsent(new SwingDialogWrapper()));
	env.setIFD(ifd);
	states = new CardStateMap();

	EstablishContextResponse ecr = env.getIFD().establishContext(new EstablishContext());
	CardRecognition cr = new CardRecognition(ifd, ecr.getContextHandle());

        em = new EventManager(cr, env, ecr.getContextHandle());
        env.setEventManager(em);
	                        
	ListIFDs listIFDs = new ListIFDs();

	listIFDs.setContextHandle(ecr.getContextHandle());
	ListIFDsResponse listIFDsResponse = ifd.listIFDs(listIFDs);
	RecognitionInfo recognitionInfo = cr.recognizeCard(listIFDsResponse.getIFDName().get(0), new BigInteger("0"));
	SALStateCallback salCallback = new SALStateCallback(cr, states);

	Connect c = new Connect();
	c.setContextHandle(ecr.getContextHandle());
	c.setIFDName(listIFDsResponse.getIFDName().get(0));
	c.setSlot(new BigInteger("0"));
	ConnectResponse connectResponse = env.getIFD().connect(c);

	ConnectionHandleType connectionHandleType = new ConnectionHandleType();
	connectionHandleType.setContextHandle(ecr.getContextHandle());
	connectionHandleType.setRecognitionInfo(recognitionInfo);
	connectionHandleType.setIFDName(listIFDsResponse.getIFDName().get(0));
	connectionHandleType.setSlotIndex(new BigInteger("0"));
	connectionHandleType.setSlotHandle(connectResponse.getSlotHandle());
	salCallback.signalEvent(EventType.CARD_RECOGNIZED, connectionHandleType);
	instance = new TinySAL(env, states);

	// init AddonManager
	UserConsent uc = new SwingUserConsent(new SwingDialogWrapper());
	AddonManager manager = new AddonManager(d, uc, states, cr, em);
	instance.setAddonManager(manager);
    }

    /**
     * Test of didAuthenticate method, of class TinySAL.
     *
     * @throws ParserConfigurationException
     */
    @Test(priority = 1)
    public void testDidAuthenticate3() throws ParserConfigurationException {
	System.out.println("didAuthenticate, PIN ADMIN, 000000");

	// get path to IRMA
	CardApplicationPath cardApplicationPath = new CardApplicationPath();
	CardApplicationPathType cardApplicationPathType = new CardApplicationPathType();
	cardApplicationPathType.setCardApplication(appIdentifier_IRMA);
	cardApplicationPath.setCardAppPathRequest(cardApplicationPathType);
	CardApplicationPathResponse cardApplicationPathResponse = instance.cardApplicationPath(cardApplicationPath);

	// connect to IRMA
	CardApplicationConnect cardApplicationConnect = new CardApplicationConnect();
	cardApplicationConnect.setCardApplicationPath(cardApplicationPathResponse.getCardAppPathResultSet().getCardApplicationPathResult()
		.get(0));
	CardApplicationConnectResponse result = instance.cardApplicationConnect(cardApplicationConnect);

	assertEquals(ECardConstants.Major.OK, result.getResult().getResultMajor());

	DIDAuthenticate parameters = new DIDAuthenticate();
	parameters.setDIDName("IRMA.LOG");
	DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	factory.setNamespaceAware(true);
	DocumentBuilder builder = factory.newDocumentBuilder();
	Document d = builder.newDocument();
	Element elemPin = d.createElementNS("urn:iso:std:iso-iec:24727:tech:schema", "Pin");
	elemPin.setTextContent("000000");
	DIDAuthenticationDataType didAuthenticationData = new DIDAuthenticationDataType();
	didAuthenticationData.getAny().add(elemPin);

	parameters.setAuthenticationProtocolData(didAuthenticationData);
	parameters.setConnectionHandle(result.getConnectionHandle());
	didAuthenticationData.setProtocol(ECardConstants.Protocol.IRMA_LOG);
	parameters.setAuthenticationProtocolData(didAuthenticationData);
	DIDAuthenticateResponse result1 = instance.didAuthenticate(parameters);

	assertEquals(result1.getAuthenticationProtocolData().getProtocol(), ECardConstants.Protocol.IRMA_LOG);
	assertEquals(ECardConstants.Major.OK, result1.getResult().getResultMajor());
	
	System.out.println("## RAW IRMA LOW");
	
	for (Element element : result1.getAuthenticationProtocolData().getAny()) {
	        byte[] logByte = new BigInteger(element.getTextContent(),16).toByteArray();
	        IdemixLogEntry logEntry  = new IdemixLogEntry(logByte);
	        logEntry.print();
        }
    }
}
