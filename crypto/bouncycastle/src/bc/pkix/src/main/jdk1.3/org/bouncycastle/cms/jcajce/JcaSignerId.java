package org.bouncycastle.cms.jcajce;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;

public class JcaSignerId
    extends SignerId
{
    private static X509Principal getPrincipal(X509Certificate cert)
    {
         try
         {
             return PrincipalUtil.getIssuerX509Principal(cert);
         }
         catch (Exception e)
         {
             throw new IllegalArgumentException("unable to extract principle");
         }
    }

    /**
     * Construct a signer identifier based on the issuer, serial number and subject key identifier (if present) of the passed in
     * certificate.
     *
     * @param certificate certificate providing the issue and serial number and subject key identifier.
     */
    public JcaSignerId(X509Certificate certificate)
    {
        super(X500Name.getInstance(getPrincipal(certificate).getEncoded()), certificate.getSerialNumber(), CMSUtils.getSubjectKeyId(certificate));
    }
}
