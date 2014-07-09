/****************************************************************************
 * Copyright (C) 2014 Radboud University Nijmegen
 * All rights reserved.
 *
 * GNU General Public License Usage
 * This file may be used under the terms of the GNU General Public
 * License version 3.0 as published by the Free Software Foundation
 * and appearing in the file LICENSE.GPL included in the packaging of
 * this file. Please review the following information to ensure the
 * GNU General Public License version 3.0 requirements will be met:
 * http://www.gnu.org/copyleft/gpl.html.
 *
 ***************************************************************************/

package org.openecard.sal.protocol.abc4trustprover;

import iso.std.iso_iec._24727.tech.schema.ConnectionHandleType;
import iso.std.iso_iec._24727.tech.schema.DIDAuthenticate;
import iso.std.iso_iec._24727.tech.schema.DIDAuthenticateResponse;
import iso.std.iso_iec._24727.tech.schema.DIDAuthenticationDataType;
import iso.std.iso_iec._24727.tech.schema.DIDScopeType;
import iso.std.iso_iec._24727.tech.schema.DIDStructureType;
import iso.std.iso_iec._24727.tech.schema.DifferentialIdentityServiceActionName;
import iso.std.iso_iec._24727.tech.schema.InputUnitType;
import iso.std.iso_iec._24727.tech.schema.PasswordAttributesType;
import iso.std.iso_iec._24727.tech.schema.PinInputType;
import iso.std.iso_iec._24727.tech.schema.Transmit;
import iso.std.iso_iec._24727.tech.schema.TransmitResponse;
import iso.std.iso_iec._24727.tech.schema.VerifyUser;
import iso.std.iso_iec._24727.tech.schema.VerifyUserResponse;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Scanner;
import java.util.Map;
import java.util.Vector;
import java.util.HashMap;
import java.io.File;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URISyntaxException;
import org.openecard.addon.sal.FunctionType;
import org.openecard.addon.sal.ProtocolStep;
import org.openecard.common.ECardException;
import org.openecard.common.WSHelper;
import org.openecard.common.apdu.common.CardResponseAPDU;
import org.openecard.common.interfaces.Dispatcher;
import org.openecard.common.sal.Assert;
import org.openecard.common.sal.anytype.ABC4TrustProverMarkerType;
import org.openecard.common.sal.state.CardStateEntry;
import org.openecard.common.sal.util.SALUtils;
import org.openecard.common.util.PINUtils;
import org.openecard.sal.protocol.abc4trustprover.anytype.ABC4TrustProverDIDAuthenticateInputType;
import org.openecard.sal.protocol.abc4trustprover.anytype.ABC4TrustProverDIDAuthenticateOutputType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import java.util.TreeMap;
import java.util.List;
import java.util.ArrayList;

import com.google.gson.Gson;

/**
 * @author Antonio de la Piedra <a.delapiedra@cs.ru.nl>
 */
public class DIDAuthenticateStep implements ProtocolStep<DIDAuthenticate, DIDAuthenticateResponse> {

    private static final Logger logger = LoggerFactory.getLogger(DIDAuthenticateStep.class);
    private final Dispatcher dispatcher;

    /* Location of the script that communicates with the abc4trust webservice (user) */
    private final String userScriptName = "/home/vmr/work/svn/academico/post-doc/future_id_clean/open-ecard/addons/abc4trust/deployment/Code/core-abce/abce-services/userFutureID.sh";
    private final String userScriptPath = "/home/vmr/work/svn/academico/post-doc/future_id_clean/open-ecard/addons/abc4trust/deployment/Code/core-abce/abce-services/";

    /** 
     *    Uncomment for debug
     *    private final String verifierScriptName = "/home/vmr/work/svn/academico/post-doc/future_id_clean/open-ecard/addons/abc4trust/deployment/Code/core-abce/abce-services/verifier.sh";
     *    private final String verifierScriptPath = "/home/vmr/work/svn/academico/post-doc/future_id_clean/open-ecard/addons/abc4trust/deployment/Code/core-abce/abce-services/";
     */
    
    /* The abc4trust webservice stores here the generated presentation token */
    private final String presentationTokenPath = "/tmp/presentationToken.xml";

    /**
     * Creates a new DIDAuthenticateStep.
     *
     * @param dispatcher Dispatcher
     */
    public DIDAuthenticateStep(Dispatcher dispatcher) {
	this.dispatcher = dispatcher;
    }

    @Override
    public FunctionType getFunctionType() {
	return FunctionType.DIDAuthenticate;
    }

    @Override
    public DIDAuthenticateResponse perform(DIDAuthenticate request, Map<String, Object> internalData) {
	DIDAuthenticateResponse response = WSHelper.makeResponse(DIDAuthenticateResponse.class, WSHelper.makeResultOK());
        Vector<byte[]> list = new Vector<byte[]>();

	try {
	    ConnectionHandleType connectionHandle = SALUtils.getConnectionHandle(request);
	    String didName = SALUtils.getDIDName(request);
	    CardStateEntry cardStateEntry = SALUtils.getCardStateEntry(internalData, connectionHandle);
	    
	    ABC4TrustProverDIDAuthenticateInputType abc4trustProverInput = new ABC4TrustProverDIDAuthenticateInputType(request.getAuthenticationProtocolData());
	    ABC4TrustProverDIDAuthenticateOutputType proofOutput = abc4trustProverInput.getOutputType();

	    byte[] cardApplication;
	    
	    if (request.getDIDScope() != null && request.getDIDScope().equals(DIDScopeType.GLOBAL)) {
		cardApplication = cardStateEntry.getImplicitlySelectedApplicationIdentifier();
	    } else {
		cardApplication = connectionHandle.getCardApplication();
	    }
	    
	    Assert.securityConditionDID(cardStateEntry, cardApplication, didName, DifferentialIdentityServiceActionName.DID_AUTHENTICATE);
	    
	    DIDStructureType didStructure = cardStateEntry.getDIDStructure(didName, cardApplication);

	    byte[] slotHandle = connectionHandle.getSlotHandle();

	    /* Read presentation policy from the verifier (e.g. the SP). */
	    String presentationPolicy = abc4trustProverInput.getPresentationPolicy();
	    
	    /* Dump presentation policy into /tmp */
	    try {
	        PrintWriter out = new PrintWriter("/tmp/presentationPolicy.xml");
	        out.println(presentationPolicy);
	        out.close();
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
                response.setResult(WSHelper.makeResult(e));
            }
	    
	    /* Generate presentation token via the user's webservice */
            try {
                Process pr = Runtime.getRuntime().exec(userScriptName, null, new File(userScriptPath));
                /* If the verifier local webservice is running in the user's machine we can
                   ensure its correctness
                
                   pr = Runtime.getRuntime().exec(verifierScriptName, null, new File(verifierScriptPath));
                */
            } catch (Exception e) {
	        logger.error(e.getMessage(), e);
	        response.setResult(WSHelper.makeResult(e));
            }
	    
	    /* Retrieve and save presentation token for SP */
	    String presentationToken = new Scanner(new File(presentationTokenPath)).useDelimiter("\\Z").next();          
            proofOutput.setPresentationToken(presentationToken);

            response.setAuthenticationProtocolData(proofOutput.getAuthDataType());	

	} catch (ECardException e) {
	    logger.error(e.getMessage(), e);
	    response.setResult(e.getResult());
	} catch (Exception e) {
	    logger.error(e.getMessage(), e);
	    response.setResult(WSHelper.makeResult(e));
	}
	return response;
    }
}
