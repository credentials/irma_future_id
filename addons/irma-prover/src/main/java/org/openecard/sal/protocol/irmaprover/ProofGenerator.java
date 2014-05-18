
/** 
* Simple class to interface an IRMA token
* into the IRMA add-on of Future ID.
*/

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

import java.util.TreeMap;
import java.util.List;
import java.util.ArrayList;

import com.google.gson.Gson;


public class ProofGenerator {

  private String serialPolicy;
  private String generationScript;
  private String generationScriptPath;

  private URI core;

  private VerifyCredentialInformation vci;
  private IdemixVerifySpecification spec;
  private CardTerminal terminal; 
  private IdemixService service;
  private IdemixCredentials ic;

   
  public ProofGenerator(String pathToConfiguration) {
   try {
    URI core = new File(System
                        .getProperty("user.dir")).toURI()
                        .resolve(pathToConfiguration);
		
    CredentialInformation.setCoreLocation(core);
    DescriptionStore.setCoreLocation(core);
    DescriptionStore.getInstance();
   } catch (Exception e) {
    /* TODO */
   }
  }
  
  public void configureIRMA(boolean abc4trustPolicy, String policy) {
   if (!abc4trustPolicy) {
    try {
     vci = new VerifyCredentialInformation("RU", "studentCard", "RU", "studentCardAll");
     spec = vci.getIdemixVerifySpecification();

     terminal = TerminalFactory.getDefault().terminals().list().get(0);            
     service = new IdemixService(new TerminalCardService(terminal));
     ic = new IdemixCredentials(new TerminalCardService(terminal));
            
     service.open();            
     spec.setCardVersion(service.getCardVersion());
    } catch (Exception e) {
     /* TODO */
    }
   } else {
    /* TODO: Extract disclosure information from ABC4Trust policy */
   }
  }

  public String generateProof(Nonce nonce) {
   Gson gson = null;
   ProtocolResponses protocolResponses = null;
   Proof proof = null;
   boolean verified = false;

   try {
    IdemixNonce n = (IdemixNonce)nonce;
    protocolResponses = service.execute(ic.requestProofCommands(spec, nonce));
    gson = new Gson();
   } catch(Exception e) {
    /* TODO */
   }

   if (gson != null)
        return gson.toJson(protocolResponses);  
   else
    return null;
  }
}
