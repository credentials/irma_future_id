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

package org.openecard.crypto.common.asn1.eac.oid;


/**
 * See BSI-TR-03110, version 2.10
 *
 * @author Moritz Horsch <horsch at cdc.informatik.tu-darmstadt.de>
 */
public class EACObjectIdentifier {

    /**
     * bsi-de OBJECT IDENTIFIER ::= {itu-t(0) identified-organization(4)
     * etsi(0) reserved(127) etsi-identified-organization(0) 7}
     */
    public static final String bsi_de = "0.4.0.127.0.7";
    /**
     * id-PK OBJECT IDENTIFIER ::= {bsi-de protocols(2) smartcard(2) 1}
     */
    public static final String id_PK = bsi_de + ".2.2.1";
    /**
     * id-TA OBJECT IDENTIFIER ::= {bsi-de protocols(2) smartcard(2) 2}
     */
    public static final String id_TA = bsi_de + ".2.2.2";
    /**
     * id-CA OBJECT IDENTIFIER ::= {bsi-de protocols(2) smartcard(2) 3}
     */
    public static final String id_CA = bsi_de + ".2.2.3";
    /**
     * id-PACE OBJECT IDENTIFIER ::= {bsi-de protocols(2) smartcard(2) 4}
     */
    public static final String id_PACE = bsi_de + ".2.2.4";
    /**
     * Restricted Identification.
     * id-RI OBJECT IDENTIFIER ::= {bsi-de protocols(2) smartcard(2) 5}
     */
    public static final String id_RI = bsi_de + ".2.2.5";
    /**
     * CardInfoLocator.
     * id-CI OBJECT IDENTIFIER ::= {bsi-de protocols(2) smartcard(2) 6}
     */
    public static final String id_CI = bsi_de + ".2.2.6";
    /**
     * eIDSecurityInfo.
     * id-eIDSecurity OBJECT IDENTIFIER ::= {bsi-de protocols(2) smartcard(2) 7}
     */
    public static final String id_eIDSecurity = bsi_de + ".2.2.7";
    /**
     * PrivilegedTerminalInfo.
     * id-CI OBJECT IDENTIFIER ::= {bsi-de protocols(2) smartcard(2) 8}
     */
    public static final String id_PT = bsi_de + ".2.2.8";


    /**
     * Authenticated Auxiliary Data. BSI-TR-03110 section A.6.5.1.
     * id-AuxiliaryData OBJECT IDENTIFIER ::= {bsi-de applications(3) mrtd(1) 4}
     */
    public static final String id_AuxiliaryData = bsi_de + ".3.1.4";
    /**
     * Age Verification. BSI-TR-03110 section A.6.5.2.
     * id-DateOfBirth OBJECT IDENTIFIER ::= {id-AuxiliaryData 1}
     */
    public static final String id_DateOfBirth = id_AuxiliaryData + ".1";
    /**
     * Document Validity Verification. BSI-TR-03110 section A.6.5.3.
     * id-DateOfExpiry OBJECT IDENTIFIER ::= {id-AuxiliaryData 2}
     */
    public static final String id_DateOfExpiry = id_AuxiliaryData + ".2";
    /**
     * Community ID Verification. BSI-TR-03110 section A.6.5.4.
     * id-CommunityID OBJECT IDENTIFIER ::= {id-AuxiliaryData 3}
     */
    public static final String id_CommunityID = id_AuxiliaryData + ".3";
    /**
     * Signature Format. BSI-TR-03110 section A.1.2.5.
     * id-SecurityObject OBJECT IDENTIFIER ::= {bsi-de applications(3) eID(2) 1}
     */
    public static final String id_SecurityObject = bsi_de + ".3.2.1";
    /**
     * Standardized Domain Parameters. BSI-TR-03110 section A.2.1.1.
     * standardizedDomainParameters OBJECT IDENTIFIER ::= {bsi-de algorithms(1) 2}
     */
    public static final String standardized_Domain_Parameters = bsi_de + ".1.2";

}
