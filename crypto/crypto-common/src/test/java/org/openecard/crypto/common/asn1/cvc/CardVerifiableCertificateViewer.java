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

package org.openecard.crypto.common.asn1.cvc;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import org.openecard.common.util.ByteUtils;
import org.openecard.common.util.StringUtils;
import org.openecard.crypto.common.asn1.eac.EFCardAccessTest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.Test;
import static org.testng.Assert.*;


/**
 *
 * @author Moritz Horsch <horsch at cdc.informatik.tu-darmstadt.de>
 */
public class CardVerifiableCertificateViewer {

    private static final Logger logger = LoggerFactory.getLogger(CHAT.class);
    private ArrayList<CardVerifiableCertificate> certs = new ArrayList<CardVerifiableCertificate>();

    public void init() {
	try {
	    byte[] cert = StringUtils.toByteArray("7F218201447F4E81FD5F290100420F444544567449446D744730303030397F494F060A04007F0007020202020386410429DE2CA270B7F1CD4A121D182F84E1B01F123D021699B427C81D8E02DD7D0D7A6FBF8F9882F3DD12916A41F320831A0E9C4AF76A42CE98F0ECAE8EBB341292A55F200C444541546D744730303030347F4C12060904007F0007030102025305000501FB075F25060102000700045F2406010201000001655E732D060904007F00070301030180203D481284343970B32B336BF6F9316AC990342D275D273CBE3855C1C08F12CECC732D060904007F0007030103028020E0BFAAA425C6673920F25F40C8DCE16086FC9C37F723D6198CFBDFA98FDA2F0C5F374082F5C7985B73C4A46976EB3CC4BC07C6377090FDAB9134BC329A5BA97665EE23564632A9C529009437975A40205E8D5DEF6C0F0621006F0C6C6D404E46ED7616");
	    certs.add(new CardVerifiableCertificate(cert));

	    cert = StringUtils.toByteArray("7F218201B67F4E82016E5F290100420E44455445535465494430303030317F4982011D060A04007F000702020202038120A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E537782207D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9832026DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B68441048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F0469978520A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7864104096EB58BFD86252238EC2652185C43C3A56C320681A21E37A8E69DDC387C0C5F5513856EFE2FDC656E604893212E29449B365E304605AC5413E75BE31E641F128701015F200E44455445535465494430303030327F4C12060904007F0007030102025305FE0F01FFFF5F25060100000902015F24060103000902015F3740141120A0FDFC011A52F3F72B387A3DC7ACA88B4868D5AE9741780B6FF8A0B49E5F55169A2D298EF5CF95935DCA0C3DF3E9D42DC45F74F2066317154961E6C746");
	    certs.add(new CardVerifiableCertificate(cert));

	    cert = StringUtils.toByteArray("7F218201B67F4E82016E5F290100420E44455445535465494430303030327F4982011D060A04007F000702020202038120A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E537782207D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9832026DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B68441048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F0469978520A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A786410474FF63AB838C73C303AC003DFEE95CF8BF55F91E8FEBCB7395D942036E47CF1845EC786EC95BB453AAC288AD023B6067913CF9B63F908F49304E5CFC8B3050DD8701015F200E44455445535465494430303030347F4C12060904007F0007030102025305FC0F13FFFF5F25060102000501015F24060105000501015F37405C035A0611B6C58F0B5261FDD009DECAB7DC7A79482D5248CCA119059B7D82B2157CF0C4A499BCF441EFDD35E294A58C0AF19A34A0762159533285ACF170A505");
	    certs.add(new CardVerifiableCertificate(cert));

	    cert = StringUtils.toByteArray("7F2181E67F4E819F5F290100420E44455445535465494430303030347F494F060A04007F00070202020203864104265CC14F619C68F660902E5A1A0222C5C0119D936999735B202F068F345DCB9670DDEB38719460ABFAF82951D0EDE6FF7B37ECAABECACD82BE96C24E146456A95F200F444544567449446D744730303030397F4C12060904007F0007030102025305400513FF875F25060102000700035F24060102010000015F374045F0948E9D66867A60B3DD73D8F7BEAF7229920ACC2F46855578B9745D3BCF3B63B57BEE15D7B1015F14D178E1D19E8604858DC8AF8F7A938B23D557147D5989");
	    certs.add(new CardVerifiableCertificate(cert));

	    certs.add(new CardVerifiableCertificate(loadTestFile("cert_cvca.cvcert")));
	    certs.add(new CardVerifiableCertificate(loadTestFile("cert_dv.cvcert")));
	    certs.add(new CardVerifiableCertificate(loadTestFile("cert_at.cvcert")));
	    certs.add(new CardVerifiableCertificate(loadTestFile("cert_at_malformed.cvcert")));

	} catch (Exception e) {
	    logger.error(e.getMessage());
	}
    }

    @Test(enabled = !true)
    public void view() throws Exception {

	init();

	for (CardVerifiableCertificate c : certs) {
	    DateFormat dateFormat = new SimpleDateFormat();

	    System.out.println("Certificate Profile Identifier: " + ByteUtils.toHexString(c.getCPI(), true));
	    System.out.println("Certification Authority Reference: " + new String(c.getCAR().toByteArray()));
	    System.out.println("Certificate Holder Reference: " + new String(c.getCHR().toByteArray()));
	    System.out.println("Role: " + c.getCHAT().getRole().name());
	    System.out.println("CHAT: " + c.getCHAT().toString());
	    System.out.println("EffectiveDate: " + dateFormat.format(c.getEffectiveDate().getTime()));
	    System.out.println("ExpirationDate: " + dateFormat.format(c.getExpirationDate().getTime()));

	    if (c.getExtensions() != null) {
		System.out.println("Extensions: ");
		System.out.println(ByteUtils.toHexString(c.getExtensions(), true));
	    }

	    System.out.println("");
	}
    }

    private byte[] loadTestFile(String file) throws Exception {
	String path = "/" + file;
	InputStream is = EFCardAccessTest.class.getResourceAsStream(path);
	ByteArrayOutputStream baos = new ByteArrayOutputStream(is.available());
	try {
	    int b;
	    while ((b = is.read()) != -1) {
		baos.write((byte) b);
	    }
	} catch (Exception e) {
	    fail(e.getMessage());
	}
	return baos.toByteArray();
    }

}
