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

package org.openecard.sal.protocol.pincompare;

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
import org.openecard.common.ClientEnv;
import org.openecard.common.ECardConstants;
import org.openecard.common.enums.EventType;
import org.openecard.common.interfaces.Dispatcher;
import org.openecard.common.sal.anytype.PINCompareMarkerType;
import org.openecard.common.sal.state.CardStateMap;
import org.openecard.common.sal.state.SALStateCallback;
import org.openecard.common.util.ByteUtils;
import org.openecard.common.util.StringUtils;
import org.openecard.gui.UserConsent;
import org.openecard.gui.swing.SwingDialogWrapper;
import org.openecard.gui.swing.SwingUserConsent;
import org.openecard.ifd.scio.IFD;
import org.openecard.recognition.CardRecognition;
import org.openecard.sal.TinySAL;
import org.openecard.sal.protocol.pincompare.anytype.PINCompareDIDAuthenticateInputType;
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
public class PINCompareProtocolTest {

    @BeforeClass
    public static void disable() {
	throw new SkipException("Test completely disabled.");
    }

    private static ClientEnv env;
    private static TinySAL instance;
    private static CardStateMap states;
    byte[] appIdentifier_ROOT = StringUtils.toByteArray("D2760001448000");
    byte[] appIdentifier_ESIGN = StringUtils.toByteArray("A000000167455349474E");

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
	AddonManager manager = new AddonManager(d, uc, states, cr, null);
	instance.setAddonManager(manager);
    }

    @Test
    public void testDIDAuthenticate() throws ParserConfigurationException {

	CardApplicationPath cardApplicationPath = new CardApplicationPath();
	CardApplicationPathType cardApplicationPathType = new CardApplicationPathType();
	cardApplicationPathType.setCardApplication(this.appIdentifier_ROOT);
	cardApplicationPath.setCardAppPathRequest(cardApplicationPathType);
	CardApplicationPathResponse cardApplicationPathResponse = instance.cardApplicationPath(cardApplicationPath);
	CardApplicationConnect cardApplicationConnect = new CardApplicationConnect();
	cardApplicationPathType = cardApplicationPathResponse.getCardAppPathResultSet().getCardApplicationPathResult()
		.get(0);
	cardApplicationConnect.setCardApplicationPath(cardApplicationPathType);
	CardApplicationConnectResponse result1 = instance.cardApplicationConnect(cardApplicationConnect);

	///
	/// Test with a pin set.
	///
	DIDAuthenticate parameters = new DIDAuthenticate();
	parameters.setDIDName("PIN.home");
	DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	factory.setNamespaceAware(true);
	DocumentBuilder builder = factory.newDocumentBuilder();
	Document d = builder.newDocument();
	Element elemPin = d.createElementNS("urn:iso:std:iso-iec:24727:tech:schema", "Pin");
	elemPin.setTextContent("123456");
	DIDAuthenticationDataType didAuthenticationData = new DIDAuthenticationDataType();
	didAuthenticationData.getAny().add(elemPin);

	PINCompareDIDAuthenticateInputType pinCompareDIDAuthenticateInputType = new PINCompareDIDAuthenticateInputType(
		didAuthenticationData);

	parameters.setAuthenticationProtocolData(didAuthenticationData);
	parameters.setConnectionHandle(result1.getConnectionHandle());
	didAuthenticationData.setProtocol(ECardConstants.Protocol.PIN_COMPARE);
	parameters.setAuthenticationProtocolData(didAuthenticationData);
	DIDAuthenticateResponse result = instance.didAuthenticate(parameters);

	assertEquals(result.getAuthenticationProtocolData().getProtocol(), ECardConstants.Protocol.PIN_COMPARE);
	assertEquals(ECardConstants.Major.OK, result.getResult().getResultMajor());
	assertEquals(result.getAuthenticationProtocolData().getAny().size(), 0);

	///
	/// Test without a pin set.
	///
	parameters = new DIDAuthenticate();
	parameters.setDIDName("PIN.home");
	didAuthenticationData = new DIDAuthenticationDataType();
	parameters.setAuthenticationProtocolData(didAuthenticationData);
	parameters.setConnectionHandle(result1.getConnectionHandle());
	didAuthenticationData.setProtocol(ECardConstants.Protocol.PIN_COMPARE);
	parameters.setAuthenticationProtocolData(didAuthenticationData);
	result = instance.didAuthenticate(parameters);

	assertEquals(result.getAuthenticationProtocolData().getProtocol(), ECardConstants.Protocol.PIN_COMPARE);
	assertEquals(ECardConstants.Major.OK, result.getResult().getResultMajor());
	assertEquals(result.getAuthenticationProtocolData().getAny().size(), 0);
    }

    @Test
    public void testDIDCreate() {
	// TODO
    }

    @Test
    public void testDIDUpdate() {
	// TODO
    }

    @Test
    public void testDIDGet() {
	CardApplicationPath cardApplicationPath = new CardApplicationPath();
	CardApplicationPathType cardApplicationPathType = new CardApplicationPathType();
	cardApplicationPathType.setCardApplication(this.appIdentifier_ROOT);
	cardApplicationPath.setCardAppPathRequest(cardApplicationPathType);
	CardApplicationPathResponse cardApplicationPathResponse = instance.cardApplicationPath(cardApplicationPath);
	CardApplicationConnect cardApplicationConnect = new CardApplicationConnect();
	cardApplicationPathType = cardApplicationPathResponse.getCardAppPathResultSet().getCardApplicationPathResult()
		.get(0);
	cardApplicationConnect.setCardApplicationPath(cardApplicationPathType);
	CardApplicationConnectResponse result1 = instance.cardApplicationConnect(cardApplicationConnect);

	DIDGet didGet = new DIDGet();
	didGet.setDIDName("PIN.home");
	didGet.setConnectionHandle(result1.getConnectionHandle());
	DIDGetResponse result = instance.didGet(didGet);
	assertEquals(result.getResult().getResultMajor(), "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok");
	assertEquals(result.getDIDStructure().getDIDName(), "PIN.home");
	assertEquals(result.getDIDStructure().getDIDMarker().getClass(), PinCompareMarkerType.class);
	PINCompareMarkerType pinCompareMarkerType = new PINCompareMarkerType(
		(PinCompareMarkerType) result.getDIDStructure().getDIDMarker());
	assertEquals(ByteUtils.toHexString(pinCompareMarkerType.getPINRef().getKeyRef()), "02");

	// test with given correct scope
	didGet = new DIDGet();
	didGet.setDIDName("PIN.home");
	didGet.setDIDScope(DIDScopeType.GLOBAL);
	didGet.setConnectionHandle(result1.getConnectionHandle());
	result = instance.didGet(didGet);
	assertEquals(result.getResult().getResultMajor(), ECardConstants.Major.OK);
	assertEquals(result.getDIDStructure().getDIDName(), "PIN.home");
	assertEquals(result.getDIDStructure().getDIDMarker().getClass(), PinCompareMarkerType.class);
	pinCompareMarkerType = new PINCompareMarkerType((PinCompareMarkerType) result.getDIDStructure().getDIDMarker());
	assertEquals(ByteUtils.toHexString(pinCompareMarkerType.getPINRef().getKeyRef()), "02");

	cardApplicationPath = new CardApplicationPath();
	cardApplicationPathType = new CardApplicationPathType();
	cardApplicationPathType.setCardApplication(this.appIdentifier_ESIGN);
	cardApplicationPath.setCardAppPathRequest(cardApplicationPathType);
	cardApplicationPathResponse = instance.cardApplicationPath(cardApplicationPath);
	cardApplicationConnect = new CardApplicationConnect();
	cardApplicationPathType = cardApplicationPathResponse.getCardAppPathResultSet().getCardApplicationPathResult()
		.get(0);
	cardApplicationConnect.setCardApplicationPath(cardApplicationPathType);
	result1 = instance.cardApplicationConnect(cardApplicationConnect);

	assertEquals(result1.getResult().getResultMajor(), ECardConstants.Major.OK);

	didGet = new DIDGet();
	didGet.setDIDName("PIN.home");
	didGet.setDIDScope(DIDScopeType.LOCAL);
	didGet.setConnectionHandle(result1.getConnectionHandle());
	result = instance.didGet(didGet);
	assertEquals(result.getResult().getResultMajor(), ECardConstants.Major.ERROR);
	assertEquals(result.getResult().getResultMinor(), ECardConstants.Minor.SAL.NAMED_ENTITY_NOT_FOUND);
    }

    /*
     * [TR-03112-7] The following functions are not supported with this protocol
     * and, when called up, relay an error message to this effect
     * /resultminor/sal#inappropriateProtocolForAction:
     * CardApplicationStartSession, Encipher, Decipher, GetRandom, Hash, Sign,
     * VerifySignature, VerifyCertificate
     */
    /**
     * This Test ensures that all functions unsupported by this protocol relay the correct error message when
     * called.
     */
    @Test
    public void testUnsupportedFunctions() {
	CardApplicationPath cardApplicationPath = new CardApplicationPath();
	CardApplicationPathType cardApplicationPathType = new CardApplicationPathType();
	cardApplicationPathType.setCardApplication(this.appIdentifier_ROOT);
	cardApplicationPath.setCardAppPathRequest(cardApplicationPathType);
	CardApplicationPathResponse cardApplicationPathResponse = instance.cardApplicationPath(cardApplicationPath);
	CardApplicationConnect cardApplicationConnect = new CardApplicationConnect();
	cardApplicationPathType = cardApplicationPathResponse.getCardAppPathResultSet().getCardApplicationPathResult()
		.get(0);
	cardApplicationConnect.setCardApplicationPath(cardApplicationPathType);
	CardApplicationConnectResponse result1 = instance.cardApplicationConnect(cardApplicationConnect);

	Encipher encipher = new Encipher();
	encipher.setDIDName("PIN.home");
	encipher.setPlainText(new byte[] { 0x0, 0x0, 0x0 });
	encipher.setConnectionHandle(result1.getConnectionHandle());
	EncipherResponse encipherResponse = instance.encipher(encipher);
	assertEquals(encipherResponse.getResult().getResultMajor(), ECardConstants.Major.ERROR);
	assertEquals(encipherResponse.getResult()
		.getResultMinor(), ECardConstants.Minor.SAL.INAPPROPRIATE_PROTOCOL_FOR_ACTION);
	// TODO remaining unsupported functions
    }

}
