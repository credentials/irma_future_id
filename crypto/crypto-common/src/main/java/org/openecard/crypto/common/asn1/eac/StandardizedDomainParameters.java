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

package org.openecard.crypto.common.asn1.eac;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.openecard.bouncycastle.jce.ECNamedCurveTable;
import org.openecard.bouncycastle.jce.spec.ElGamalParameterSpec;


/**
 * See RFC 5114, http://tools.ietf.org/html/rfc5114
 *
 * @author Moritz Horsch <horsch@cdc.informatik.tu-darmstadt.de>
 */
public final class StandardizedDomainParameters extends DomainParameters {

    private final static Map<Integer, Object> map = new HashMap<Integer, Object>();

    // See RFC 5114, Section 2.1. 1024-bit MODP Group with 160-bit Prime Order Subgroup
    static {
	BigInteger p = new BigInteger("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16);
	BigInteger g = new BigInteger("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16);
	ElGamalParameterSpec gfp_1024_160 = new ElGamalParameterSpec(p, g);
	map.put(0, gfp_1024_160);
    }

    // See RFC 5114, Section 2.1. 2048-bit MODP Group with 224-bit Prime Order Subgroup
    static {
	BigInteger p = new BigInteger("AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A317091883681286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F", 16);
	BigInteger g = new BigInteger("AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA", 16);
	ElGamalParameterSpec gfp_2048_224 = new ElGamalParameterSpec(p, g);
	map.put(1, gfp_2048_224);
    }

    // See RFC 5114, Section 2.1. 2048-bit MODP Group with 256-bit Prime Order Subgroup
    static {
	BigInteger p = new BigInteger("87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597", 16);
	BigInteger g = new BigInteger("3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659", 16);
	ElGamalParameterSpec gfp_2048_256 = new ElGamalParameterSpec(p, g);
	map.put(2, gfp_2048_256);
    }

    // See BSI-TR-03110 version 2.05 section A.2.1.1.
    static {
//        map.put(0, "");
//        map.put(1, "");
//        map.put(2, "");
	// 3 - 7 RFU
	map.put(8, "secp192r1");
	map.put(9, "BrainpoolP192r1");
	map.put(10, "secp224r1");
	map.put(11, "BrainpoolP256r1");
	map.put(12, "secp256r1");
	map.put(13, "BrainpoolP256r1");
	map.put(14, "BrainpoolP320r1");
	map.put(15, "secp384r1");
	map.put(16, "BrainpoolP384r1");
	map.put(17, "BrainpoolP512r1");
	map.put(18, "secp521r1");
	// 19 - 31 RFU
    }

    /**
     * Instantiates a new standardized domain parameters.
     *
     * @param index the index of the standardized domain parameters
     */
    public StandardizedDomainParameters(int index) {
	Object value = map.get(index);

	if (value == null) {
	    throw new IllegalArgumentException("Wrong index for standardized domain parameter");
	} else {
	    if (index >= 0 && index <= 2) {
		domainParameter = (AlgorithmParameterSpec) value;
	    } else if (index >= 8 && index <= 18) {
		domainParameter = ECNamedCurveTable.getParameterSpec(value.toString());
	    }
	}
    }

}
