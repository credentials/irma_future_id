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

import java.util.TreeMap;


/**
 *
 * @author Tobias Wich <tobias.wich@ecsec.de>
 */
public class ECardConstants {

    private static final String ECARD_PREFIX = "http://www.bsi.bund.de/ecard/api/1.1/";
    private static final String MAJOR_PREFIX = ECARD_PREFIX + "resultmajor#";
    private static final String DSS_PREFIX   = "urn:oasis:names:tc:dss:1.0:";
    private static final String MINOR_PREFIX = ECARD_PREFIX + "resultminor/";
    private static final String APP_PREFIX   = MINOR_PREFIX + "al";   // Application Layer
    private static final String DP_PREFIX    = MINOR_PREFIX + "dp";   // Dispatcher
    private static final String IL_PREFIX    = MINOR_PREFIX + "il";   // Identity Layer
    private static final String SAL_PREFIX   = MINOR_PREFIX + "sal";  // Service Access Layer
    private static final String IFD_PREFIX   = MINOR_PREFIX + "ifdl"; // Interface Device Layer


    //
    // Inofficial Constants
    //

    public static final int CONTEXT_HANDLE_DEFAULT_SIZE = 16;
    public static final int SLOT_HANDLE_DEFAULT_SIZE = 24;

    public static final String UNKNOWN_CARD = "http://bsi.bund.de/cif/unknown";
    public static final String PAOS_NEXT = ECARD_PREFIX + "PAOS/GetNextCommand";

    public static final String ACTOR_NEXT = "http://schemas.xmlsoap.org/soap/actor/next";
    public static final String SOAP_ENVELOPE = "http://schemas.xmlsoap.org/soap/envelope/";
    public static final String PAOS_VERSION_11 = "urn:liberty:paos:2003-08";
    public static final String PAOS_VERSION_20 = "urn:liberty:paos:2006-08";
    public static final String WS_ADDRESSING = "http://www.w3.org/2005/03/addressing";


    public static class CIF {

	public static final String GET_SPECIFIED = ECARD_PREFIX + "cardinfo/action#getSpecifiedFile";
	public static final String GET_RELATED = ECARD_PREFIX + "cardinfo/action#getRelatedFiles";
	public static final String GET_OTHER = ECARD_PREFIX + "cardinfo/action#getOtherFiles";

    };

    public static class Profile {

	public static final String ECSEC = "http://ws.ecsec.de";
	public static final String ECARD_1_1 = "http://www.bsi.bund.de/ecard/api/1.1";

    };

    public static class Protocol {

	public static final String PIN_COMPARE    = "urn:oid:1.3.162.15480.3.0.9";
	public static final String MUTUAL_AUTH    = "urn:oid:1.3.162.15480.3.0.12";
	public static final String EAC_GENERIC    = "urn:oid:1.3.162.15480.3.0.14";
	public static final String EAC2           = "urn:oid:1.3.162.15480.3.0.14.2";
	public static final String RSA_AUTH       = "urn:oid:1.3.162.15480.3.0.15";
	public static final String GENERIC_CRYPTO = "urn:oid:1.3.162.15480.3.0.25";
	public static final String TERMINAL_AUTH  = "urn:oid:0.4.0.127.0.7.2.2.2";
	public static final String CHIP_AUTH      = "urn:oid:0.4.0.127.0.7.2.2.3";
	public static final String PACE           = "urn:oid:0.4.0.127.0.7.2.2.4";
	public static final String RESTRICTED_ID  = "urn:oid:0.4.0.127.0.7.2.2.5";

	public static final String IRMA_PROVER	  	  = "urn:oid:23.0.0.0.0.0.0.0.5";
	public static final String ABC4Trust_PROVER	  = "urn:oid:24.0.0.0.0.0.0.0.5";
    };

    public static class IFD {

	public static class Protocol {

	    public static final String T0 = "urn:iso:std:iso-iec:7816:-3:tech:protocols:T-equals-0";
	    public static final String T1 = "urn:iso:std:iso-iec:7816:-3:tech:protocols:T-equals-1";
	    public static final String T2 = "urn:iso:std:iso-iec:10536:tech:protocols:T-equals-2";
	    public static final String TYPE_A = "urn:iso:std:iso-iec:14443:-2:tech:protocols:Type-A";
	    public static final String TYPE_B = "urn:iso:std:iso-iec:14443:-2:tech:protocols:Type-B";

	};

    };

    //
    // Major values
    //

    public static class Major {

	public static final String OK = MAJOR_PREFIX + "ok";
	public static final String PENDING = DSS_PREFIX + "profiles:asynchronousprocessing:resultmajor:Pending";
	public static final String WARN = MAJOR_PREFIX + "warning";
	public static final String ERROR = MAJOR_PREFIX + "error";
	public static final String NEXT = MAJOR_PREFIX + "nextRequest";

    };


    //
    // Minor values
    //

    public static class Minor {

	public static class App {

	    public static final String NO_PERM = APP_PREFIX + "/common#noPermission";
	    public static final String INT_ERROR = APP_PREFIX + "/common#internalError";
	    public static final String PARM_ERROR = APP_PREFIX + "/common#parameterError";
	    public static final String UNKNOWN_ERROR = APP_PREFIX + "/common#unknownError";
	    public static final String INCORRECT_PARM = APP_PREFIX + "/common#incorrectParameter";

	};

	public static class Disp {

	    public static final String INVALID_CHANNEL_HANDLE = DP_PREFIX + "#invalidChannelHandle";

	};

	public static class Ident {
	    
	    private static final String IL_IS_PREFIX = IL_PREFIX + "il";   // Identity Layer - Identity Service

	    public static final String AUTH_FAIL = IL_IS_PREFIX + "#authenticationFailure";

	    public static final String UNKNOWN_POLICY = "unknownPolicyWarning";
	    public static final String UNKNOWN_ATTRIBUTE = "unknownAttributeWarning";
	    public static final String UNKNOWN_DEFAULT_URI = "unknownDefaultURIWarning";

	    public static class Sig {

	    };

	    public static class Enc {

	    };

	};

	public static class SAL {

	    public static final String UNKNOWN_HANDLE = SAL_PREFIX + "#unknownConnectionHandle";
	    public static final String UNKNOWN_CARDTYPE = SAL_PREFIX + "#unknownCardType";

	    public static final String PROTOCOL_NOT_RECOGNIZED = SAL_PREFIX + "#protocolNotRecognized";
	    public static final String INAPPROPRIATE_PROTOCOL_FOR_ACTION = SAL_PREFIX + "#inappropriateProtocolForAction";

	    public static final String REPO_UNREACHABLE = SAL_PREFIX + "/support#cardInfoRepositoryUnreachable";

	    public static final String SECURITY_CONDITINON_NOT_SATISFIED = SAL_PREFIX + "#securityConditionNotSatisfied";

	    public static final String NAMED_ENTITY_NOT_FOUND = SAL_PREFIX + "#namedEntityNotFound";

	    public static final String CANCELLATION_BY_USER = SAL_PREFIX + "#cancellationByUser";

	    public static final String INVALID_SIGNATURE = SAL_PREFIX + "#invalidSignature";

	};

	public static class IFD {

	    public static final String CANCELLATION_BY_USER = IFD_PREFIX + "#cancellationByUser";

	    public static final String INVALID_CONTEXT_HANDLE = IFD_PREFIX + "/common#invalidContextHandle";
	    public static final String INVALID_SLOT_HANDLE = IFD_PREFIX + "/common#invalidSlotHandle";
	    public static final String TIMEOUT_ERROR = IFD_PREFIX + "/common#timeoutError";

	    public static final String IFD_SHARING_VIOLATION = IFD_PREFIX + "/terminal#IFDSharingViolation";
	    public static final String NO_CARD = IFD_PREFIX + "/terminal#noCard";
	    public static final String UNKNOWN_ACTION = IFD_PREFIX + "/terminal#unknownAction";
	    public static final String UNKNOWN_IFD = IFD_PREFIX + "/terminal#unknownIFD";
	    public static final String UNKNOWN_SLOT = IFD_PREFIX + "/terminal#unknownSlot";

	    // Not yet specified by the BSI
	    public static final String PASSWORD_SUSPENDED = IFD_PREFIX + "/passwordSuspended";
	    public static final String PASSWORD_BLOCKED = IFD_PREFIX + "/passwordBlocked";
	    public static final String PASSWORD_ERROR = IFD_PREFIX + "/passwordError";
	    public static final String PASSWORD_DEACTIVATED = IFD_PREFIX + "/passwordDeactivated";
	    public static final String AUTHENTICATION_FAILED = IFD_PREFIX + "/authenticationFailed";
	    public static final String UNKNOWN_ERROR = IFD_PREFIX + "/unknownError";

	    public static class IO {

		private static final String IO_PREFIX = IFD_PREFIX + "/IO";

		public static final String NO_TRANSACTION_STARTED = IFD_PREFIX + "#noTransactionStarted";

		public static final String UNKNOWN_DISPLAY_INDEX = IO_PREFIX + "#unknownDisplayIndex";
		public static final String UNKNOWN_OUTPUT_DEVICE = IO_PREFIX + "#unknownOutputDevice";
		public static final String UNKNOWN_INPUT_UNIT = IO_PREFIX + "#unknownInputUnit";
		public static final String UNKNOWN_PIN_FORMAT = IO_PREFIX + "#unknownPINFormat";
		public static final String CANCEL_NOT_POSSIBLE = IO_PREFIX + "#cancelNotPossible";

	    };

	};

    };

    private static final TreeMap<String,String> msgMap = new TreeMap<String, String>();

    static {
	// major types
	msgMap.put(Major.OK, "No error occurred during execution of the operation.");
	msgMap.put(Major.WARN, "If the result of the operation is in principle OK, but there is a detail which may require closer investigation, a warning is given as a response.");
	msgMap.put(Major.ERROR, "An error occurred during execution of the operation.");
	msgMap.put(Major.NEXT, "This result appears if at least one more request is expected within a protocol.");

	// minor App
	// minor App common
	msgMap.put(Minor.App.NO_PERM, "Use of the function by the client application is not permitted.");
	msgMap.put(Minor.App.INT_ERROR, "Internal error.");
	msgMap.put(Minor.App.PARM_ERROR, "There was some problem with a provided or omitted parameter.");

	// minor SAL
	msgMap.put(Minor.SAL.UNKNOWN_HANDLE, "Unknown connection handle specified.");
	msgMap.put(Minor.SAL.UNKNOWN_CARDTYPE, "Unknown card type specified.");
	// minor SAL support
	msgMap.put(Minor.SAL.REPO_UNREACHABLE, "The CardInfo repository server is not accessible");
    }

    public static String URI2Msg(final String uri) {
	String result = msgMap.get(uri);
	return (result != null) ? result : "";
    }

}
