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

package org.openecard.control.module.tctoken;

import generated.TCTokenType;
import iso.std.iso_iec._24727.tech.schema.CardApplicationConnect;
import iso.std.iso_iec._24727.tech.schema.CardApplicationConnectResponse;
import iso.std.iso_iec._24727.tech.schema.CardApplicationPath;
import iso.std.iso_iec._24727.tech.schema.CardApplicationPathResponse;
import iso.std.iso_iec._24727.tech.schema.CardApplicationPathType;
import iso.std.iso_iec._24727.tech.schema.ConnectionHandleType;
import iso.std.iso_iec._24727.tech.schema.StartPAOSResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.openecard.common.ECardConstants;
import org.openecard.common.WSHelper;
import org.openecard.common.WSHelper.WSException;
import org.openecard.common.interfaces.Dispatcher;
import org.openecard.common.interfaces.DispatcherException;
import org.openecard.common.sal.state.CardStateEntry;
import org.openecard.common.sal.state.CardStateMap;
import org.openecard.common.util.HttpRequestLineUtils;
import org.openecard.control.module.tctoken.gui.InsertCardDialog;
import org.openecard.gui.UserConsent;
import org.openecard.recognition.CardRecognition;
import org.openecard.transport.paos.PAOSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Transport binding agnostic TCToken handler. <br/>
 * This handler supports the following transports:
 * <ul>
 * <li>PAOS</li>
 * </ul>
 * <p>
 * This handler supports the following security protocols:
 * <ul>
 * <li>TLS</li>
 * <li>TLS-PSK</li>
 * <li>PLS-PSK-RSA</li>
 * </ul>
 *
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 * @author Moritz Horsch <horsch@cdc.informatik.tu-darmstadt.de>
 */
public class GenericTCTokenHandler {

    private static final Logger logger = LoggerFactory.getLogger(GenericTCTokenHandler.class);

    private final ExecutorService executor;

    private final CardStateMap cardStates;
    private final Dispatcher dispatcher;
    private final UserConsent gui;
    private final CardRecognition rec;

    /**
     * Creates a TCToken handler instances and initializes it with the given parameters.
     *
     * @param cardStates Instance of the card states managed by the application.
     * @param dispatcher The dispatcher used to deliver the messages to the webservice interface implementations.
     * @param gui The implementation of the user consent interface.
     * @param rec The card recognition engine.
     */
    public GenericTCTokenHandler(CardStateMap cardStates, Dispatcher dispatcher, UserConsent gui, CardRecognition rec) {
	this.executor = Executors.newCachedThreadPool();

	this.cardStates = cardStates;
	this.dispatcher = dispatcher;
	this.gui = gui;
	this.rec = rec;
    }

    /**
     * Processes the activation request sent via the localhost binding.
     *
     * @param requestURI The request URI of the localhost server. This is not the tcTokenURL but the complete request
     *   URI.
     * @return A TCToken request for further processing in the TCToken handler.
     * @throws UnsupportedEncodingException If the URI contains an invalid query string.
     * @throws TCTokenException If the TCToken could not be fetched. That means either the URL is invalid, the server
     *   was not reachable or the returned value was not a TCToken or TCToken like structure.
     */
    public TCTokenRequest parseRequestURI(URI requestURI) throws UnsupportedEncodingException, TCTokenException {
	String queryStr = requestURI.getRawQuery();
	Map<String, String> queries = HttpRequestLineUtils.transform(queryStr);

	TCTokenRequest result;
	if (queries.containsKey("tcTokenURL")) {
	    result = parseTCTokenRequestURI(queries);
	    result.setTokenFromObject(false);
	    return result;
	} else if (queries.containsKey("activationObject")) {
	    result = parseObjectURI(queries);
	    result.setTokenFromObject(true);
	    return result;
	}

	throw new TCTokenException("No suitable set of parameters given in the request.");
    }

    private TCTokenRequest parseTCTokenRequestURI(Map<String, String> queries) throws TCTokenException {
	TCTokenRequest tcTokenRequest = new TCTokenRequest();

	for (Map.Entry<String, String> next : queries.entrySet()) {
	    String k = next.getKey();
	    String v = next.getValue();

	    if (k.equals("tcTokenURL")) {
		if (v != null && ! v.isEmpty()) {
		    try {
			TCTokenType token = TCTokenFactory.generateTCToken(new URL(v));
			tcTokenRequest.setTCToken(token);
		    } catch (MalformedURLException ex) {
			String msg = "The tcTokenURL parameter contains an invalid URL: " + v;
			throw new TCTokenException(msg, ex);
		    } catch (IOException ex) {
			throw new TCTokenException("Failed to fetch TCToken.", ex);
		    }
		} else {
		    throw new TCTokenException("Parameter tcTokenURL contains no value.");
		}

	    } else if (k.equals("ifdName")) {
		if (v != null && ! v.isEmpty()) {
		    tcTokenRequest.setIFDName(v);
		} else {
		    throw new TCTokenException("Parameter ifdName contains no value.");
		}

	    } else if (k.equals("contextHandle")) {
		if (v != null && ! v.isEmpty()) {
		    tcTokenRequest.setContextHandle(v);
		} else {
		    throw new TCTokenException("Parameter contextHandle contains no value.");
		}

	    } else if (k.equals("slotIndex")) {
		if (v != null && ! v.isEmpty()) {
		    tcTokenRequest.setSlotIndex(v);
		} else {
		    throw new TCTokenException("Parameter slotIndex contains no value.");
		}
	    } else if (k.equals("cardType")) {
		if (v != null && ! v.isEmpty()) {
		    tcTokenRequest.setCardType(v);
		} else {
		    throw new TCTokenException("Parameter cardType contains no value.");
		}
	    } else {
		logger.info("Unknown query element: {}", k);
	    }
	}

	return tcTokenRequest;
    }

    private TCTokenRequest parseObjectURI(Map<String, String> queries) throws TCTokenException {
	TCTokenRequest tcTokenRequest = new TCTokenRequest();

	for (Map.Entry<String, String> next : queries.entrySet()) {
	    String k = next.getKey();
	    String v = next.getValue();

	    if ("activationObject".equals(k)) {
		TCTokenType token = TCTokenFactory.generateTCToken(v);
		tcTokenRequest.setTCToken(token);
	    }
	}

	return tcTokenRequest;
    }

    /**
     * Gets the first handle of the given card type.
     *
     * @param type The card type to get the first handle for.
     * @return Handle describing the given card type or null if none is present.
     */
    private ConnectionHandleType getFirstHandle(String type) {
	String cardName = rec.getTranslatedCardName(type);
	ConnectionHandleType conHandle = new ConnectionHandleType();
	ConnectionHandleType.RecognitionInfo recInfo = new ConnectionHandleType.RecognitionInfo();
	recInfo.setCardType(type);
	conHandle.setRecognitionInfo(recInfo);
	Set<CardStateEntry> entries = cardStates.getMatchingEntries(conHandle);
	if (entries.isEmpty()) {
	    InsertCardDialog uc = new InsertCardDialog(gui, cardStates, type, cardName);
	    return uc.show();
	} else {
	    return entries.iterator().next().handleCopy();
	}
    }

    /**
     * Performs the actual PAOS procedure.
     * Connects the given card, establishes the HTTP channel and talks to the server. Afterwards disconnects the card.
     *
     * @param token The TCToken containing the connection parameters.
     * @param connectionHandle The handle of the card that will be used.
     * @return A TCTokenResponse indicating success or failure.
     * @throws DispatcherException If there was a problem dispatching a request from the server.
     * @throws PAOSException If there was a transport error.
     */
    private TCTokenResponse doPAOS(TCTokenRequest tokenRequest, ConnectionHandleType connectionHandle)
	    throws PAOSException, DispatcherException {
	TCTokenType token = tokenRequest.getTCToken();
	try {
	    // Perform a CardApplicationPath and CardApplicationConnect to connect to the card application
	    CardApplicationPath appPath = new CardApplicationPath();
	    appPath.setCardAppPathRequest(connectionHandle);
	    CardApplicationPathResponse appPathRes = (CardApplicationPathResponse) dispatcher.deliver(appPath);

	    // Check CardApplicationPathResponse
	    WSHelper.checkResult(appPathRes);

	    CardApplicationConnect appConnect = new CardApplicationConnect();
	    List<CardApplicationPathType> pathRes;
	    pathRes = appPathRes.getCardAppPathResultSet().getCardApplicationPathResult();
	    appConnect.setCardApplicationPath(pathRes.get(0));
	    CardApplicationConnectResponse appConnectRes;
	    appConnectRes = (CardApplicationConnectResponse) dispatcher.deliver(appConnect);
	    // Update ConnectionHandle. It now includes a SlotHandle.
	    connectionHandle = appConnectRes.getConnectionHandle();

	    // Check CardApplicationConnectResponse
	    WSHelper.checkResult(appConnectRes);

	    // send StartPAOS
	    PAOSTask task = new PAOSTask(dispatcher, connectionHandle, tokenRequest);
	    Future<StartPAOSResponse> paosTask = executor.submit(task);
	    if (! tokenRequest.isTokenFromObject()) {
		// wait for computation to finish
		paosTask.get();
	    }

	    TCTokenResponse response = new TCTokenResponse();
	    response.setRefreshAddress(new URL(token.getRefreshAddress()));
	    response.setResult(WSHelper.makeResultOK());

	    return response;
	} catch (WSException ex) {
	    String msg = "Failed to connect to card.";
	    logger.error(msg, ex);
	    throw new DispatcherException(msg, ex);
	} catch (InvocationTargetException ex) {
	    logger.error(ex.getMessage(), ex);
	    throw new DispatcherException(ex);
	} catch (MalformedURLException ex) {
	    logger.error(ex.getMessage(), ex);
	    throw new PAOSException(ex);
	} catch (InterruptedException ex) {
	    logger.error(ex.getMessage(), ex);
	    throw new PAOSException(ex);
	} catch (ExecutionException ex) {
	    logger.error(ex.getMessage(), ex);
	    // perform conversion of ExecutionException from the Future to the really expected exceptions
	    if (ex.getCause() instanceof PAOSException) {
		throw (PAOSException) ex.getCause();
	    } else if (ex.getCause() instanceof DispatcherException) {
		throw (DispatcherException) ex.getCause();
	    } else {
		throw new PAOSException(ex);
	    }
	}
    }

    /**
     * Activates the client according to the received TCToken.
     *
     * @param request The activation request containing the TCToken.
     * @return The response containing the result of the activation process.
     */
    public TCTokenResponse handleActivate(TCTokenRequest request) {
	ConnectionHandleType connectionHandle = null;
	TCTokenResponse response = new TCTokenResponse();

	byte[] requestedContextHandle = request.getContextHandle();
	String ifdName = request.getIFDName();
	BigInteger requestedSlotIndex = request.getSlotIndex();

	if (requestedContextHandle == null || ifdName == null || requestedSlotIndex == null) {
	    // use dumb activation without explicitly specifying the card and terminal
	    // see TR-03112-7 v 1.1.2 (2012-02-28) sec. 3.2
	    connectionHandle = getFirstHandle(request.getCardType());
	} else {
	    // we know exactly which card we want
	    ConnectionHandleType requestedHandle = new ConnectionHandleType();
	    requestedHandle.setContextHandle(requestedContextHandle);
	    requestedHandle.setIFDName(ifdName);
	    requestedHandle.setSlotIndex(requestedSlotIndex);

	    Set<CardStateEntry> matchingHandles = cardStates.getMatchingEntries(requestedHandle);
	    if (! matchingHandles.isEmpty()) {
		connectionHandle = matchingHandles.toArray(new CardStateEntry[] {})[0].handleCopy();
	    }
	}

	if (connectionHandle == null) {
	    String msg = "No card available for the given ConnectionHandle.";
	    logger.error(msg);
	    response.setResult(WSHelper.makeResultError(ECardConstants.Minor.SAL.CANCELLATION_BY_USER, msg));
	    return response;
	}

	try {
	    return doPAOS(request, connectionHandle);
	} catch (DispatcherException w) {
	    logger.error(w.getMessage(), w);
	    // TODO: check for better matching minor type
	    response.setResult(WSHelper.makeResultError(ECardConstants.Minor.App.INCORRECT_PARM, w.getMessage()));
	    return response;
	} catch (PAOSException w) {
	    logger.error(w.getMessage(), w);
	    Throwable innerException = w.getCause();
	    if(innerException != null && innerException instanceof WSException) {
		response.setResult(((WSException) innerException).getResult());
	    } else {
		// TODO: check for better matching minor type
		response.setResult(WSHelper.makeResultError(ECardConstants.Minor.App.INCORRECT_PARM, w.getMessage()));
	    } 
	    return response;
	}
    }

}
