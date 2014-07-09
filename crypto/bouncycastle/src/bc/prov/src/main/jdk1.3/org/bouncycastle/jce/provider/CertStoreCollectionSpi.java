package org.bouncycastle.jce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CRL;
import org.bouncycastle.jce.cert.CRLSelector;
import org.bouncycastle.jce.cert.CertSelector;
import org.bouncycastle.jce.cert.CertStoreException;
import org.bouncycastle.jce.cert.CertStoreParameters;
import org.bouncycastle.jce.cert.CertStoreSpi;
import java.security.cert.Certificate;
import org.bouncycastle.jce.cert.CollectionCertStoreParameters;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

public class CertStoreCollectionSpi extends CertStoreSpi
{
    private CollectionCertStoreParameters params;

    public CertStoreCollectionSpi(CertStoreParameters params)
        throws InvalidAlgorithmParameterException
    {
        super(params);

        if (!(params instanceof CollectionCertStoreParameters))
        {
            throw new InvalidAlgorithmParameterException("org.bouncycastle.jce.provider.CertStoreCollectionSpi: parameter must be a CollectionCertStoreParameters object\n" +  params.toString());
        }

        this.params = (CollectionCertStoreParameters)params;
    }

    public Collection engineGetCertificates(
        CertSelector selector)
        throws CertStoreException 
    {
        List        col = new ArrayList();
        Iterator    iter = params.getCollection().iterator();

        if (selector == null)
        {
            while (iter.hasNext())
            {
                Object obj = iter.next();

                if (obj instanceof Certificate)
                {
                    col.add(obj);
                }
            }
        }
        else
        {
            while (iter.hasNext())
            {
                Object obj = iter.next();

                if ((obj instanceof Certificate) && selector.match((Certificate)obj))
                {
                    col.add(obj);
                }
            }
        }
        
        return col;
    }
    

    public Collection engineGetCRLs(
        CRLSelector selector)
        throws CertStoreException 
    {
        List        col = new ArrayList();
        Iterator    iter = params.getCollection().iterator();

        if (selector == null)
        {
            while (iter.hasNext())
            {
                Object obj = iter.next();

                if (obj instanceof CRL)
                {
                    col.add(obj);
                }
            }
        }
        else
        {
            while (iter.hasNext())
            {
                Object obj = iter.next();

                if ((obj instanceof CRL) && selector.match((CRL)obj))
                {
                    col.add(obj);
                }
            }
        }
        
        return col;
    }    
}
