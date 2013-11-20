package org.bouncycastle.cavp;

import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.List;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.cavp.jca.JcaDigestProcessorFactory;
import org.bouncycastle.cavp.jce.JceCryptoProcessorFactory;
import org.bouncycastle.cavp.test.AesTest;
import org.bouncycastle.cavp.test.CryptoProcessorFactory;
import org.bouncycastle.cavp.test.DigestProcessorFactory;
import org.bouncycastle.cavp.test.DsaTest;
import org.bouncycastle.cavp.test.ProcessorFactoryProducer;
import org.bouncycastle.cavp.test.ShaTest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ProviderTest
    extends TestCase
{
    public void testAES()
        throws Exception
    {
        AesTest aesTest = new AesTest("data/aes", new ProviderProcessorFactoryProducer());

        List<String> errors = aesTest.run();

        if (!errors.isEmpty())
        {
            printErrors(errors);
        }
    }

    public void testSHA()
        throws Exception
    {
        ShaTest shaTest = new ShaTest("data/sha", new ProviderProcessorFactoryProducer());

        List<String> errors = shaTest.run();

        if (!errors.isEmpty())
        {
            printErrors(errors);
        }
    }

    public void testDSA()
        throws Exception
    {
        DsaTest dsaTest = new DsaTest("data/dsa", new ProviderProcessorFactoryProducer());

        List<String> errors = dsaTest.run();

        if (!errors.isEmpty())
        {
            printErrors(errors);
        }
    }

    private void printErrors(List<String> errors)
    {
        for (String error : errors)
        {
            System.err.println(error);
        }

        fail(errors.size() + " test error(s) detected");
    }

    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
    {
        Security.addProvider(new BouncyCastleProvider());
        
        TestSuite suite = new TestSuite("CAVP Provider Test");

        suite.addTestSuite(ProviderTest.class);

        return suite;
    }

    private static class ProviderProcessorFactoryProducer
        implements ProcessorFactoryProducer
    {
        public CryptoProcessorFactory createCryptoProcessorFactory(String algorithm)
            throws GeneralSecurityException
        {
            return new JceCryptoProcessorFactory(algorithm);
        }

        public DigestProcessorFactory createDigestProcessorFactory(String digest)
            throws GeneralSecurityException
        {
            return new JcaDigestProcessorFactory(digest);
        }
    }
}
