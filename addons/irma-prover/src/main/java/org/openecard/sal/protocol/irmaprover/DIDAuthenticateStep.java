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

package org.openecard.sal.protocol.irmaprover;

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
import java.util.Map;
import java.util.Vector;
import java.util.HashMap;
import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import org.openecard.addon.sal.FunctionType;
import org.openecard.addon.sal.ProtocolStep;
import org.openecard.common.ECardException;
import org.openecard.common.WSHelper;
import org.openecard.common.apdu.common.CardResponseAPDU;
import org.openecard.common.interfaces.Dispatcher;
import org.openecard.common.sal.Assert;
import org.openecard.common.sal.anytype.IRMAPROVERMarkerType;
import org.openecard.common.sal.state.CardStateEntry;
import org.openecard.common.sal.util.SALUtils;
import org.openecard.common.util.PINUtils;
import org.openecard.common.util.IRMAUtils;
import org.openecard.sal.protocol.irmaprover.anytype.IRMAPROVERDIDAuthenticateInputType;
import org.openecard.sal.protocol.irmaprover.anytype.IRMAPROVERDIDAuthenticateOutputType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ibm.zurich.idmx.issuance.Issuer;
import com.ibm.zurich.idmx.issuance.Message;
import com.ibm.zurich.idmx.showproof.Proof;
import com.ibm.zurich.idmx.showproof.Verifier;
import com.ibm.zurich.idmx.showproof.predicates.CLPredicate;
import com.ibm.zurich.idmx.showproof.predicates.Predicate;
import com.ibm.zurich.idmx.showproof.predicates.Predicate.PredicateType;
import com.ibm.zurich.idmx.utils.Constants;
import com.ibm.zurich.idmx.utils.SystemParameters;

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.BaseCredentials;
import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.Nonce;
import org.irmacard.credentials.idemix.IdemixCredentials;
import org.irmacard.credentials.idemix.IdemixNonce;
import org.irmacard.credentials.idemix.IdemixPrivateKey;
import org.irmacard.credentials.idemix.spec.IdemixIssueSpecification;
import org.irmacard.credentials.idemix.spec.IdemixVerifySpecification;
import org.irmacard.credentials.idemix.util.CredentialInformation;
import org.irmacard.credentials.idemix.util.IssueCredentialInformation;
import org.irmacard.credentials.idemix.util.VerifyCredentialInformation;
import org.irmacard.idemix.util.IdemixLogEntry;
import org.irmacard.credentials.info.CredentialDescription;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.idemix.IdemixService;
import org.irmacard.idemix.IdemixSmartcard;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import net.sourceforge.scuba.smartcards.TerminalCardService;
import net.sourceforge.scuba.smartcards.CardService;
import net.sourceforge.scuba.smartcards.CardServiceException;  
import net.sourceforge.scuba.smartcards.CommandAPDU;
import net.sourceforge.scuba.smartcards.ProtocolCommand;
import net.sourceforge.scuba.smartcards.ProtocolCommands;
import net.sourceforge.scuba.smartcards.ProtocolResponses;
import net.sourceforge.scuba.smartcards.ResponseAPDU;

import com.ibm.zurich.idmx.utils.Utils;

/**
 * Implements the DIDAuthenticate step of the PIN Compare protocol.
 * See TR-03112, version 1.1.2, part 7, section 4.1.5.
 *
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 * @author Moritz Horsch <horsch@cdc.informatik.tu-darmstadt.de>
 */
public class DIDAuthenticateStep implements ProtocolStep<DIDAuthenticate, DIDAuthenticateResponse> {

    private static final Logger logger = LoggerFactory.getLogger(DIDAuthenticateStep.class);
    private final Dispatcher dispatcher;

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
	    
	    IRMAPROVERDIDAuthenticateInputType pinCompareInput = new IRMAPROVERDIDAuthenticateInputType(request.getAuthenticationProtocolData());
	    IRMAPROVERDIDAuthenticateOutputType pinCompareOutput = pinCompareInput.getOutputType();

	    byte[] cardApplication;
	    
	    if (request.getDIDScope() != null && request.getDIDScope().equals(DIDScopeType.GLOBAL)) {
		cardApplication = cardStateEntry.getImplicitlySelectedApplicationIdentifier();
	    } else {
		cardApplication = connectionHandle.getCardApplication();
	    }
	    
	    Assert.securityConditionDID(cardStateEntry, cardApplication, didName, DifferentialIdentityServiceActionName.DID_AUTHENTICATE);
	    
	    DIDStructureType didStructure = cardStateEntry.getDIDStructure(didName, cardApplication);
	    IRMAPROVERMarkerType pinCompareMarker = new IRMAPROVERMarkerType(didStructure.getDIDMarker());

	    byte keyRef = pinCompareMarker.getPINRef().getKeyRef()[0];
	    PasswordAttributesType attributes = pinCompareMarker.getPasswordAttributes();
	    String rawPIN = pinCompareInput.getPIN();
	    	    	    	    	    
	    byte[] slotHandle = connectionHandle.getSlotHandle();
	    
	    /*
	        TODO
	    
	        1. ARGUMENTS FOR:
	            1. CREDENTIAL THAT MUST BE USED AND OPTIONS
                2. REPLACE CREDENTIAL_IDEMIX BY APDUs (IRMAUtil.java)
	    */
	    
	    // 1. Initialize credential informacion (XML)
	    
            URI core = new File(System
                       .getProperty("user.dir")).toURI()
                       .resolve("irma_configuration/");
		
            CredentialInformation.setCoreLocation(core);
            DescriptionStore.setCoreLocation(core);
            DescriptionStore.getInstance();
            
            // 2. Obtain credential spec
          
            VerifyCredentialInformation vci = new VerifyCredentialInformation("RU", "studentCard", "RU", "studentCardAll");
            //VerifyCredentialInformation vci = new VerifyCredentialInformation("RU",
	    //			"studentCard", "RU", "studentCardNone");

            //VerifyCredentialInformation vci = new VerifyCredentialInformation(
	    //			"Surfnet", "root", "Surfnet", "rootAll");

            IdemixVerifySpecification spec = vci.getIdemixVerifySpecification();

            CardTerminal terminal = TerminalFactory.getDefault().terminals().list().get(0);            
            IdemixService service = new IdemixService(new TerminalCardService(terminal));
            IdemixCredentials ic = new IdemixCredentials(new TerminalCardService(terminal));
            
            service.open();            
            spec.setCardVersion(service.getCardVersion());

            // 3. Get a nonce from the verifier 
            
            Nonce nonce = new IdemixNonce(new BigInteger(rawPIN, 10)); 
                    
            // 4. Generate proof
	    
            /* 
            * Since the bug of 1/20 make fail the proof, maybe
            * we can check its verification before sending it.
            *
            * If that fails, we generate a new one.
            */
	    
	    Proof proof = null;
	    boolean verified = false;
	    
	    while(verified == false || proof == null) {
                ProtocolResponses protocolResponses = service.execute(ic.requestProofCommands(spec, nonce));
                IdemixNonce n = (IdemixNonce)nonce;
                proof = IdemixSmartcard.processBuildProofResponses(spec.getCardVersion(), protocolResponses,
                    spec.getProofSpec());

                if (proof == null) {
                    System.out.println("Failed to generate proof.");
                }
		
                Verifier verifier = new Verifier(spec.getProofSpec(), proof, n.getNonce());
                verified = verifier.verify();
            
                if (!verified) {
                    System.out.println("Verification failed");
                }
            }
           
           /* DEBUG, self-verification, Copyright Pim Vullers. 
            
            Attributes attributes = new Attributes();
            HashMap<String, BigInteger> values = verifier.getRevealedValues();

            String prefix = "";
            
            for (Predicate pred : spec.getProofSpec().getPredicates()) {
                if (pred.getPredicateType() == PredicateType.CL) {
                    prefix = ((CLPredicate) pred).getTempCredName() + Constants.DELIMITER;
                    break;
		}
            }

            for (String id : values.keySet()) {
                String name = id.replace(prefix, "");
		attributes.add(name, values.get(id).toByteArray());
            }

            if (!attributes.isValid()) {
                System.err.println("Credential expired!");
                throw new CredentialsException("The credential has expired.");
            }		
		
            if (attributes == null) {
                System.out.println("The proof does not verify");
            } else {
                System.out.println("Proof verified");
            }
		
            attributes.print();
            
            */
  
            //pinCompareOutput.setPinStatus(data);
            response.setAuthenticationProtocolData(pinCompareOutput.getAuthDataType());	

	} catch (ECardException e) {
	    logger.error(e.getMessage(), e);
	    response.setResult(e.getResult());
        } catch (CardServiceException e) {
            System.out.println("Verification encountered error " + e);
	} catch (Exception e) {
	    logger.error(e.getMessage(), e);
	    response.setResult(WSHelper.makeResult(e));
	}

	return response;
    }
}
