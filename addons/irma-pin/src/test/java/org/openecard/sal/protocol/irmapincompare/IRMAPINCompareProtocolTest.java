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

package org.openecard.sal.protocol.irmapincompare;

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
import org.openecard.common.sal.anytype.IRMAPINCompareMarkerType;
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
import org.openecard.sal.protocol.irmapincompare.anytype.IRMAPINCompareDIDAuthenticateInputType;
import org.openecard.transport.dispatcher.MessageDispatcher;
import org.testng.SkipException;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import static org.testng.Assert.*;


/**
 *
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 */
public class IRMAPINCompareProtocolTest {

//    @BeforeClass
//    public static void disable() {
//	throw new SkipException("Test completely disabled.");
//    }

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
     * PIN ATTRIBUTE
     * @throws ParserConfigurationException
     */
    @Test(priority = 1) 
    public void testDidAuthenticate1() throws ParserConfigurationException {
        System.out.println("### testDIDAuthenticate - irma-pin");
	System.out.println("## didAuthenticate, PIN ATTRIBUTE, 0000");

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
	parameters.setDIDName("PIN.ATTRIBUTE");
	DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	factory.setNamespaceAware(true);
	DocumentBuilder builder = factory.newDocumentBuilder();
	Document d = builder.newDocument();
	Element elemPin = d.createElementNS("urn:iso:std:iso-iec:24727:tech:schema", "Pin");
	elemPin.setTextContent("0000");
	DIDAuthenticationDataType didAuthenticationData = new DIDAuthenticationDataType();
	didAuthenticationData.getAny().add(elemPin);

	//PINCompareDIDAuthenticateInputType pinCompareDIDAuthenticateInputType = new PINCompareDIDAuthenticateInputType(
	//	didAuthenticationData);

	parameters.setAuthenticationProtocolData(didAuthenticationData);
	parameters.setConnectionHandle(result.getConnectionHandle());
	didAuthenticationData.setProtocol(ECardConstants.Protocol.IRMA_PIN_COMPARE);
	parameters.setAuthenticationProtocolData(didAuthenticationData);
	DIDAuthenticateResponse result1 = instance.didAuthenticate(parameters);

	assertEquals(result1.getAuthenticationProtocolData().getProtocol(), ECardConstants.Protocol.IRMA_PIN_COMPARE);
	assertEquals(ECardConstants.Major.OK, result1.getResult().getResultMajor());
	assertEquals(result1.getAuthenticationProtocolData().getAny().size(), 0);
    }

    /**
     * Test of didUpdate method, of class TinySAL.
     */
    @Test(priority = 2) 
    public void testDidUpdate1() throws ParserConfigurationException {
        System.out.println("### testDIDUpdate - irma-pin");
	System.out.println("## didUpdate, PIN ATTRIBUTE, 1111");

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

        DIDUpdate parameters = new DIDUpdate();
	parameters.setDIDName("PIN.ATTRIBUTE");
	DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	factory.setNamespaceAware(true);
	DocumentBuilder builder = factory.newDocumentBuilder();
	Document d = builder.newDocument();

	Element elemPin = d.createElementNS("urn:iso:std:iso-iec:24727:tech:schema", "Pin");
	elemPin.setTextContent("1111");
	
	Element elemOldPin = d.createElementNS("urn:iso:std:iso-iec:24727:tech:schema", "OldPin");
	elemOldPin.setTextContent("0000");

	Element elemAdminPin = d.createElementNS("urn:iso:std:iso-iec:24727:tech:schema", "AdminPin");
	elemAdminPin.setTextContent("000000");

	DIDUpdateDataType didUpdateData = new DIDUpdateDataType();

	didUpdateData.getAny().add(elemPin);
	didUpdateData.getAny().add(elemOldPin);
	didUpdateData.getAny().add(elemAdminPin);

	didUpdateData.setProtocol(ECardConstants.Protocol.IRMA_PIN_COMPARE);
	parameters.setConnectionHandle(result.getConnectionHandle());
 	parameters.setDIDUpdateData(didUpdateData);

	DIDUpdateResponse result1 = instance.didUpdate(parameters);
	assertEquals(ECardConstants.Major.OK, result1.getResult().getResultMajor());
    }

    @Test(priority = 3) 
    public void testDidAuthenticate2() throws ParserConfigurationException {
        System.out.println("### testDIDAuthenticate - irma-pin");
	System.out.println("## didAuthenticate, PIN ATTRIBUTE, 1111");

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
	parameters.setDIDName("PIN.ATTRIBUTE");
	DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	factory.setNamespaceAware(true);
	DocumentBuilder builder = factory.newDocumentBuilder();
	Document d = builder.newDocument();
	Element elemPin = d.createElementNS("urn:iso:std:iso-iec:24727:tech:schema", "Pin");
	elemPin.setTextContent("1111");
	DIDAuthenticationDataType didAuthenticationData = new DIDAuthenticationDataType();
	didAuthenticationData.getAny().add(elemPin);

	//PINCompareDIDAuthenticateInputType pinCompareDIDAuthenticateInputType = new PINCompareDIDAuthenticateInputType(
	//	didAuthenticationData);

	parameters.setAuthenticationProtocolData(didAuthenticationData);
	parameters.setConnectionHandle(result.getConnectionHandle());
	didAuthenticationData.setProtocol(ECardConstants.Protocol.IRMA_PIN_COMPARE);
	parameters.setAuthenticationProtocolData(didAuthenticationData);
	DIDAuthenticateResponse result1 = instance.didAuthenticate(parameters);

	assertEquals(result1.getAuthenticationProtocolData().getProtocol(), ECardConstants.Protocol.IRMA_PIN_COMPARE);
	assertEquals(ECardConstants.Major.OK, result1.getResult().getResultMajor());
	assertEquals(result1.getAuthenticationProtocolData().getAny().size(), 0);
    }

    /**
     * Test of didUpdate method, of class TinySAL.
     */
    @Test(priority = 4) 
    public void testDidUpdate2() throws ParserConfigurationException {
        System.out.println("### testDIDUpdate - irma-pin");
	System.out.println("## didAuthenticate, PIN ATTRIBUTE, 0000");

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

        DIDUpdate parameters = new DIDUpdate();
	parameters.setDIDName("PIN.ATTRIBUTE");
	DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	factory.setNamespaceAware(true);
	DocumentBuilder builder = factory.newDocumentBuilder();
	Document d = builder.newDocument();

	Element elemPin = d.createElementNS("urn:iso:std:iso-iec:24727:tech:schema", "Pin");
	elemPin.setTextContent("0000");
	
	Element elemOldPin = d.createElementNS("urn:iso:std:iso-iec:24727:tech:schema", "OldPin");
	elemOldPin.setTextContent("1111");

	Element elemAdminPin = d.createElementNS("urn:iso:std:iso-iec:24727:tech:schema", "AdminPin");
	elemAdminPin.setTextContent("000000");

	DIDUpdateDataType didUpdateData = new DIDUpdateDataType();

	didUpdateData.getAny().add(elemPin);
	didUpdateData.getAny().add(elemOldPin);
	didUpdateData.getAny().add(elemAdminPin);

	didUpdateData.setProtocol(ECardConstants.Protocol.IRMA_PIN_COMPARE);
	parameters.setConnectionHandle(result.getConnectionHandle());
 	parameters.setDIDUpdateData(didUpdateData);

	DIDUpdateResponse result1 = instance.didUpdate(parameters);
	assertEquals(ECardConstants.Major.OK, result1.getResult().getResultMajor());
    }

    /**
     * Test of didAuthenticate method, of class TinySAL.
     *
     * @throws ParserConfigurationException
     */
    @Test(priority = 5)
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
	parameters.setDIDName("PIN.ADMIN");
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
	didAuthenticationData.setProtocol(ECardConstants.Protocol.IRMA_PIN_COMPARE);
	parameters.setAuthenticationProtocolData(didAuthenticationData);
	DIDAuthenticateResponse result1 = instance.didAuthenticate(parameters);

	assertEquals(result1.getAuthenticationProtocolData().getProtocol(), ECardConstants.Protocol.IRMA_PIN_COMPARE);
	assertEquals(ECardConstants.Major.OK, result1.getResult().getResultMajor());
	assertEquals(result1.getAuthenticationProtocolData().getAny().size(), 0);
    }

    /**
     * Test of didUpdate method, of class TinySAL.
     */
    @Test(priority = 6) 
    public void testDidUpdate3() throws ParserConfigurationException {
	System.out.println("didUpdate, PIN ADMIN, change PIN from 000000 to 111111 -- connecting");

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

	System.out.println("didUpdate, PIN ADMIN, change PIN from 000000 to 111111 -- connected");

	// change PIN from 000000 to 111111

        DIDUpdate parameters = new DIDUpdate();
	parameters.setDIDName("PIN.ADMIN");
	DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	factory.setNamespaceAware(true);
	DocumentBuilder builder = factory.newDocumentBuilder();
	Document d = builder.newDocument();

	Element elemPin = d.createElementNS("urn:iso:std:iso-iec:24727:tech:schema", "Pin");
	elemPin.setTextContent("111111");
	
	Element elemOldPin = d.createElementNS("urn:iso:std:iso-iec:24727:tech:schema", "OldPin");
	elemOldPin.setTextContent("000000");

	Element elemAdminPin = d.createElementNS("urn:iso:std:iso-iec:24727:tech:schema", "AdminPin");
	elemAdminPin.setTextContent("000000");

	DIDUpdateDataType didUpdateData = new DIDUpdateDataType();

	didUpdateData.getAny().add(elemPin);
	didUpdateData.getAny().add(elemOldPin);
	didUpdateData.getAny().add(elemAdminPin);

	didUpdateData.setProtocol(ECardConstants.Protocol.PIN_COMPARE);
	parameters.setConnectionHandle(result.getConnectionHandle());
 	parameters.setDIDUpdateData(didUpdateData);

	System.out.println("didUpdate, PIN ADMIN, change PIN from 000000 to 111111 -- updating");

	DIDUpdateResponse result1 = instance.didUpdate(parameters);
	assertEquals(ECardConstants.Major.OK, result1.getResult().getResultMajor());
}

    @Test(priority = 7)
    public void testDidAuthenticate4() throws ParserConfigurationException {
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
	parameters.setDIDName("PIN.ADMIN");
	DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	factory.setNamespaceAware(true);
	DocumentBuilder builder = factory.newDocumentBuilder();
	Document d = builder.newDocument();
	Element elemPin = d.createElementNS("urn:iso:std:iso-iec:24727:tech:schema", "Pin");
	elemPin.setTextContent("111111");
	DIDAuthenticationDataType didAuthenticationData = new DIDAuthenticationDataType();
	didAuthenticationData.getAny().add(elemPin);

	parameters.setAuthenticationProtocolData(didAuthenticationData);
	parameters.setConnectionHandle(result.getConnectionHandle());
	didAuthenticationData.setProtocol(ECardConstants.Protocol.IRMA_PIN_COMPARE);
	parameters.setAuthenticationProtocolData(didAuthenticationData);
	DIDAuthenticateResponse result1 = instance.didAuthenticate(parameters);

	assertEquals(result1.getAuthenticationProtocolData().getProtocol(), ECardConstants.Protocol.IRMA_PIN_COMPARE);
	assertEquals(ECardConstants.Major.OK, result1.getResult().getResultMajor());
	assertEquals(result1.getAuthenticationProtocolData().getAny().size(), 0);
    }

    @Test(priority = 8) 
    public void testDidUpdate4() throws ParserConfigurationException {
	System.out.println("didUpdate, PIN ADMIN, change PIN from 111111 to 000000 -- connecting");

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

	System.out.println("didUpdate, PIN ADMIN, change PIN from 111111 to 000000 -- connected");

	// change PIN from 000000 to 111111

        DIDUpdate parameters = new DIDUpdate();
	parameters.setDIDName("PIN.ADMIN");
	DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	factory.setNamespaceAware(true);
	DocumentBuilder builder = factory.newDocumentBuilder();
	Document d = builder.newDocument();

	Element elemPin = d.createElementNS("urn:iso:std:iso-iec:24727:tech:schema", "Pin");
	elemPin.setTextContent("000000");
	
	Element elemOldPin = d.createElementNS("urn:iso:std:iso-iec:24727:tech:schema", "OldPin");
	elemOldPin.setTextContent("111111");

	Element elemAdminPin = d.createElementNS("urn:iso:std:iso-iec:24727:tech:schema", "AdminPin");
	elemAdminPin.setTextContent("000000");

	DIDUpdateDataType didUpdateData = new DIDUpdateDataType();

	didUpdateData.getAny().add(elemPin);
	didUpdateData.getAny().add(elemOldPin);
	didUpdateData.getAny().add(elemAdminPin);

	didUpdateData.setProtocol(ECardConstants.Protocol.PIN_COMPARE);
	parameters.setConnectionHandle(result.getConnectionHandle());
 	parameters.setDIDUpdateData(didUpdateData);

	System.out.println("didUpdate, PIN ADMIN, change PIN from 111111 to 000000 -- updating");

	DIDUpdateResponse result1 = instance.didUpdate(parameters);
	assertEquals(ECardConstants.Major.OK, result1.getResult().getResultMajor());
}



}
