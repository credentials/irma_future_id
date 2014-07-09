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

package org.openecard.sal.protocol.abc4trustprover;

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
import org.openecard.common.sal.anytype.ABC4TrustProverMarkerType;
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

import java.util.Random;
import java.util.Map;
import java.util.HashMap;
import java.io.File;
import java.io.IOException;

import java.net.URI;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import java.util.TreeMap;
import java.util.List;
import java.util.ArrayList;

import com.google.gson.Gson;


public class ABC4TrustProverProtocolTest {

    private static ClientEnv env;
    private static TinySAL instance;
    private static CardStateMap states;
    private static EventManager em;

    byte[] appIdentifier_ABC4Trust = Hex.decode("F84142433474727573");

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
    public void testDidAuthenticate1() throws ParserConfigurationException, CardException, IOException {

        /* Example presentation policy sent by a certain SP */
        String presentationPolicy = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><PresentationPolicyAlternatives xmlns=\"http://abc4trust.eu/wp2/abcschemav1.0\" Version=\"1.0\"><PresentationPolicy PolicyUID=\"http://MyFavoriteSoccerTeam/policies/match/842/vip\"><Message><Nonce>2Hkb+I0tbst/dA==</Nonce><TokenGeneratorlicationData>        MyFavoriteSoccerTeam vs. OtherTeam      </TokenGeneratorlicationData></Message><Credential Alias=\"#ticket\"><CredentialSpecAlternatives><CredentialSpecUID>http://MyFavoriteSoccerTeam/tickets/vip</CredentialSpecUID></CredentialSpecAlternatives><IssuerAlternatives><IssuerParametersUID RevocationInformationUID=\"urn:abc4trust:1.0:revocation:information/4hjqwl0htcw1hbc\">http://ticketcompany/MyFavoriteSoccerTeam/issuance:idemix</IssuerParametersUID></IssuerAlternatives><DisclosedAttribute AttributeType=\"City\" DataHandlingPolicy=\"http://www.sweetdreamsuites.com/policies/creditcards\"/><DisclosedAttribute AttributeType=\"State\" DataHandlingPolicy=\"http://www.sweetdreamsuites.com/policies/creditcards\"/></Credential><AttributePredicate Function=\"urn:oasis:names:tc:xacml:1.0:function:date-equal\"><Attribute CredentialAlias=\"#ticket\" AttributeType=\"IDValidFrom\"/><ConstantValue xmlns:abc=\"http://abc4trust.eu/wp2/abcschemav1.0\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">2002-11-01Z</ConstantValue></AttributePredicate></PresentationPolicy></PresentationPolicyAlternatives>";

	// get path to ABC4Trust
	CardApplicationPath cardApplicationPath = new CardApplicationPath();
	CardApplicationPathType cardApplicationPathType = new CardApplicationPathType();
	cardApplicationPathType.setCardApplication(appIdentifier_ABC4Trust);
	cardApplicationPath.setCardAppPathRequest(cardApplicationPathType);
	CardApplicationPathResponse cardApplicationPathResponse = instance.cardApplicationPath(cardApplicationPath);

	// connect to ABC4Trust
	CardApplicationConnect cardApplicationConnect = new CardApplicationConnect();
	cardApplicationConnect.setCardApplicationPath(cardApplicationPathResponse.getCardAppPathResultSet().getCardApplicationPathResult()
		.get(0));
	CardApplicationConnectResponse result = instance.cardApplicationConnect(cardApplicationConnect);

	assertEquals(ECardConstants.Major.OK, result.getResult().getResultMajor());

	DIDAuthenticate parameters = new DIDAuthenticate();
	parameters.setDIDName("ABC4Trust.PROVER");
	DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	factory.setNamespaceAware(true);
	DocumentBuilder builder = factory.newDocumentBuilder();
	Document d = builder.newDocument();

	Element elemPresentationPolicy = d.createElementNS("urn:iso:std:iso-iec:24727:tech:schema", "PresentationPolicy");
	elemPresentationPolicy.setTextContent(presentationPolicy); 
	
	DIDAuthenticationDataType didAuthenticationData = new DIDAuthenticationDataType();

	didAuthenticationData.getAny().add(elemPresentationPolicy);

	parameters.setAuthenticationProtocolData(didAuthenticationData);
	parameters.setConnectionHandle(result.getConnectionHandle());
	didAuthenticationData.setProtocol(ECardConstants.Protocol.ABC4Trust_PROVER);
	parameters.setAuthenticationProtocolData(didAuthenticationData);
	DIDAuthenticateResponse result1 = instance.didAuthenticate(parameters);

	assertEquals(result1.getAuthenticationProtocolData().getProtocol(), ECardConstants.Protocol.ABC4Trust_PROVER);
	assertEquals(ECardConstants.Major.OK, result1.getResult().getResultMajor());
    }
}
