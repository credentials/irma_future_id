package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Vector;

/**
 * A temporary class to use LegacyTlsAuthentication
 *
 * @deprecated
 */
public class LegacyTlsClient
    extends DefaultTlsClient
{
    /**
     * @deprecated
     */
    protected CertificateVerifyer verifyer;

    /**
     * @deprecated
     */
    public LegacyTlsClient(CertificateVerifyer verifyer)
    {
        super();

        this.verifyer = verifyer;
    }

    /**
     * @deprecated
     */
    public LegacyTlsClient(CertificateVerifyer verifyer, String fqdn)
    {
        super(fqdn);

        this.verifyer = verifyer;
    }

    /**
     * @deprecated
     */
    public LegacyTlsClient(CertificateVerifyer verifyer, Vector serverNames)
    {
        super(serverNames);

        this.verifyer = verifyer;
    }

    public TlsAuthentication getAuthentication()
        throws IOException
    {
        return new LegacyTlsAuthentication(verifyer);
    }
}
