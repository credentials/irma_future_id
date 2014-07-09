package org.bouncycastle.cms.test;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.jce.cert.CertStore;
import org.bouncycastle.jce.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509AttributeCertificate;
import org.bouncycastle.x509.X509CollectionStoreParameters;
import org.bouncycastle.x509.X509Store;

public class SignedDataStreamTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final String TEST_MESSAGE = "Hello World!";
    private static String          _signDN;
    private static KeyPair         _signKP;  
    private static X509Certificate _signCert;

    private static String          _origDN;
    private static KeyPair         _origKP;
    private static X509Certificate _origCert;

    private static String          _reciDN;
    private static KeyPair         _reciKP;
    private static X509Certificate _reciCert;
    
    private static KeyPair         _origDsaKP;
    private static X509Certificate _origDsaCert;

    private static X509CRL         _signCrl;
    private static X509CRL         _origCrl;

    private static boolean         _initialised = false;

    private static final JcaX509CertSelectorConverter selectorConverter = new JcaX509CertSelectorConverter();

    public SignedDataStreamTest(String name) 
    {
        super(name);
    }
    
    private static void init()
        throws Exception
    {
        if (!_initialised)
        {
            _initialised = true;
            
            _signDN   = "O=Bouncy Castle, C=AU";
            _signKP   = CMSTestUtil.makeKeyPair();  
            _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);
    
            _origDN   = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            _origKP   = CMSTestUtil.makeKeyPair();
            _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);
    
            _origDsaKP   = CMSTestUtil.makeDsaKeyPair();
            _origDsaCert = CMSTestUtil.makeCertificate(_origDsaKP, _origDN, _signKP, _signDN);
            
            _reciDN   = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP   = CMSTestUtil.makeKeyPair();
            _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);

            _signCrl  = CMSTestUtil.makeCrl(_signKP);
            _origCrl  = CMSTestUtil.makeCrl(_origKP);
        }
    }
    
    private void verifySignatures(CMSSignedDataParser sp, byte[] contentDigest) 
        throws Exception
    {
        CertStore               certStore = sp.getCertificatesAndCRLs("Collection", BC);
        SignerInformationStore  signers = sp.getSignerInfos();
        
        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();
    
        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certStore.getCertificates(selectorConverter.getCertSelector(signer.getSID()));
    
            Iterator        certIt = certCollection.iterator();
            X509Certificate cert = (X509Certificate)certIt.next();
    
            assertEquals(true, signer.verify(cert, BC));
            
            if (contentDigest != null)
            {
                assertTrue(MessageDigest.isEqual(contentDigest, signer.getContentDigest()));
            }
        }

        Collection certColl = certStore.getCertificates(null);
        Collection crlColl = certStore.getCRLs(null);

        assertEquals(certColl.size(), sp.getCertificates("Collection", BC).getMatches(null).size());
        assertEquals(crlColl.size(), sp.getCRLs("Collection", BC).getMatches(null).size());
    }
    
    private void verifySignatures(CMSSignedDataParser sp) 
        throws Exception
    {
        verifySignatures(sp, null);
    }

    private void verifyEncodedData(ByteArrayOutputStream bOut)
        throws Exception
    {
        CMSSignedDataParser sp;
        sp = new CMSSignedDataParser(bOut.toByteArray());
    
        sp.getSignedContent().drain();
        
        verifySignatures(sp);
        
        sp.close();
    }

    private void checkSigParseable(byte[] sig)
        throws Exception
    {
        CMSSignedDataParser sp = new CMSSignedDataParser(sig);
        sp.getVersion();
        CMSTypedStream sc = sp.getSignedContent();
        if (sc != null)
        {
            sc.drain();
        }
        sp.getCertificatesAndCRLs("Collection", BC);
        sp.getSignerInfos();
        sp.close();
    }

    public void testEarlyInvalidKeyException() throws Exception
    {
        try
        {
            CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
            gen.addSigner( _origKP.getPrivate(), _origCert,
                "DSA", // DOESN'T MATCH KEY ALG
                CMSSignedDataStreamGenerator.DIGEST_SHA1, BC);

            fail("Expected InvalidKeyException in addSigner");
        }
        catch (InvalidKeyException e)
        {
            // Ignore
        }
    }

    public void testEarlyNoSuchAlgorithmException() throws Exception
    {
        try
        {
            CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
            gen.addSigner( _origKP.getPrivate(), _origCert,
                CMSSignedDataStreamGenerator.DIGEST_SHA1, // BAD OID!
                CMSSignedDataStreamGenerator.DIGEST_SHA1, BC);

            fail("Expected NoSuchAlgorithmException in addSigner");
        }
        catch (NoSuchAlgorithmException e)
        {
            // Ignore
        }
    }

    public void testSha1EncapsulatedSignature()
        throws Exception
    {
        byte[]  encapSigData = Base64.decode(
                  "MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEH"
                + "AaCAJIAEDEhlbGxvIFdvcmxkIQAAAAAAAKCCBGIwggINMIIBdqADAgECAgEF"
                + "MA0GCSqGSIb3DQEBBAUAMCUxFjAUBgNVBAoTDUJvdW5jeSBDYXN0bGUxCzAJ"
                + "BgNVBAYTAkFVMB4XDTA1MDgwNzA2MjU1OVoXDTA1MTExNTA2MjU1OVowJTEW"
                + "MBQGA1UEChMNQm91bmN5IENhc3RsZTELMAkGA1UEBhMCQVUwgZ8wDQYJKoZI"
                + "hvcNAQEBBQADgY0AMIGJAoGBAI1fZGgH9wgC3QiK6yluH6DlLDkXkxYYL+Qf"
                + "nVRszJVYl0LIxZdpb7WEbVpO8fwtEgFtoDsOdxyqh3dTBv+L7NVD/v46kdPt"
                + "xVkSNHRbutJVY8Xn4/TC/CDngqtbpbniMO8n0GiB6vs94gBT20M34j96O2IF"
                + "73feNHP+x8PkJ+dNAgMBAAGjTTBLMB0GA1UdDgQWBBQ3XUfEE6+D+t+LIJgK"
                + "ESSUE58eyzAfBgNVHSMEGDAWgBQ3XUfEE6+D+t+LIJgKESSUE58eyzAJBgNV"
                + "HRMEAjAAMA0GCSqGSIb3DQEBBAUAA4GBAFK3r1stYOeXYJOlOyNGDTWEhZ+a"
                + "OYdFeFaS6c+InjotHuFLAy+QsS8PslE48zYNFEqYygGfLhZDLlSnJ/LAUTqF"
                + "01vlp+Bgn/JYiJazwi5WiiOTf7Th6eNjHFKXS3hfSGPNPIOjvicAp3ce3ehs"
                + "uK0MxgLAaxievzhFfJcGSUMDMIICTTCCAbagAwIBAgIBBzANBgkqhkiG9w0B"
                + "AQQFADAlMRYwFAYDVQQKEw1Cb3VuY3kgQ2FzdGxlMQswCQYDVQQGEwJBVTAe"
                + "Fw0wNTA4MDcwNjI1NTlaFw0wNTExMTUwNjI1NTlaMGUxGDAWBgNVBAMTD0Vy"
                + "aWMgSC4gRWNoaWRuYTEkMCIGCSqGSIb3DQEJARYVZXJpY0Bib3VuY3ljYXN0"
                + "bGUub3JnMRYwFAYDVQQKEw1Cb3VuY3kgQ2FzdGxlMQswCQYDVQQGEwJBVTCB"
                + "nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAgHCJyfwV6/V3kqSu2SOU2E/K"
                + "I+N0XohCMUaxPLLNtNBZ3ijxwaV6JGFz7siTgZD/OGfzir/eZimkt+L1iXQn"
                + "OAB+ZChivKvHtX+dFFC7Vq+E4Uy0Ftqc/wrGxE6DHb5BR0hprKH8wlDS8wSP"
                + "zxovgk4nH0ffUZOoDSuUgjh3gG8CAwEAAaNNMEswHQYDVR0OBBYEFLfY/4EG"
                + "mYrvJa7Cky+K9BJ7YmERMB8GA1UdIwQYMBaAFDddR8QTr4P634sgmAoRJJQT"
                + "nx7LMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQEEBQADgYEADIOmpMd6UHdMjkyc"
                + "mIE1yiwfClCsGhCK9FigTg6U1G2FmkBwJIMWBlkeH15uvepsAncsgK+Cn3Zr"
                + "dZMb022mwtTJDtcaOM+SNeuCnjdowZ4i71Hf68siPm6sMlZkhz49rA0Yidoo"
                + "WuzYOO+dggzwDsMldSsvsDo/ARyCGOulDOAxggEvMIIBKwIBATAqMCUxFjAU"
                + "BgNVBAoTDUJvdW5jeSBDYXN0bGUxCzAJBgNVBAYTAkFVAgEHMAkGBSsOAwIa"
                + "BQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEP"
                + "Fw0wNTA4MDcwNjI1NTlaMCMGCSqGSIb3DQEJBDEWBBQu973mCM5UBOl9XwQv"
                + "lfifHCMocTANBgkqhkiG9w0BAQEFAASBgGxnBl2qozYKLgZ0ygqSFgWcRGl1"
                + "LgNuE587LtO+EKkgoc3aFqEdjXlAyP8K7naRsvWnFrsB6pUpnrgI9Z8ZSKv8"
                + "98IlpsSSJ0jBlEb4gzzavwcBpYbr2ryOtDcF+kYmKIpScglyyoLzm+KPXOoT"
                + "n7MsJMoKN3Kd2Vzh6s10PFgeAAAAAAAA");

        CMSSignedDataParser     sp = new CMSSignedDataParser(encapSigData);

        sp.getSignedContent().drain();

        verifySignatures(sp);
    }
    
    public void testSHA1WithRSANoAttributes()
        throws Exception
    {
        List                certList = new ArrayList();
        CMSProcessable      msg = new CMSProcessableByteArray(TEST_MESSAGE.getBytes());
    
        certList.add(_origCert);
        certList.add(_signCert);
    
        CertStore           certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), BC);
    
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
    
        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataGenerator.DIGEST_SHA1);
    
        gen.addCertificatesAndCRLs(certs);
    
        CMSSignedData s = gen.generate(CMSSignedDataGenerator.DATA, msg, false, BC, false);

        CMSSignedDataParser     sp = new CMSSignedDataParser(
                new CMSTypedStream(new ByteArrayInputStream(TEST_MESSAGE.getBytes())), s.getEncoded());
        
        sp.getSignedContent().drain();
        
        //
        // compute expected content digest
        //
        MessageDigest md = MessageDigest.getInstance("SHA1", BC);
        
        verifySignatures(sp, md.digest(TEST_MESSAGE.getBytes()));
    }
    
    public void testDSANoAttributes()
        throws Exception
    {
        List                certList = new ArrayList();
        CMSProcessable      msg = new CMSProcessableByteArray(TEST_MESSAGE.getBytes());
    
        certList.add(_origDsaCert);
        certList.add(_signCert);
    
        CertStore           certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), BC);
    
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
    
        gen.addSigner(_origDsaKP.getPrivate(), _origDsaCert, CMSSignedDataGenerator.DIGEST_SHA1);
    
        gen.addCertificatesAndCRLs(certs);
    
        CMSSignedData s = gen.generate(CMSSignedDataGenerator.DATA, msg, false, BC, false);
    
        CMSSignedDataParser     sp = new CMSSignedDataParser(
                new CMSTypedStream(new ByteArrayInputStream(TEST_MESSAGE.getBytes())), s.getEncoded());
        
        sp.getSignedContent().drain();
        
        //
        // compute expected content digest
        //
        MessageDigest md = MessageDigest.getInstance("SHA1", BC);
        
        verifySignatures(sp, md.digest(TEST_MESSAGE.getBytes()));
    }
    
    public void testSHA1WithRSA()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        certList.add(_origCert);
        certList.add(_signCert);

        certList.add(_signCrl);
        certList.add(_origCrl);

        CertStore           certsAndCrls = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), BC);
    
        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
    
        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, BC);
    
        gen.addCertificatesAndCRLs(certsAndCrls);
    
        OutputStream sigOut = gen.open(bOut);
    
        sigOut.write(TEST_MESSAGE.getBytes());
        
        sigOut.close();

        checkSigParseable(bOut.toByteArray());

        CMSSignedDataParser     sp = new CMSSignedDataParser(
                new CMSTypedStream(new ByteArrayInputStream(TEST_MESSAGE.getBytes())), bOut.toByteArray());
    
        sp.getSignedContent().drain();
        
        //
        // compute expected content digest
        //
        MessageDigest md = MessageDigest.getInstance("SHA1", BC);
        
        verifySignatures(sp, md.digest(TEST_MESSAGE.getBytes()));
        
        //
        // try using existing signer
        //
        gen = new CMSSignedDataStreamGenerator();
    
        gen.addSigners(sp.getSignerInfos());
        
        gen.addCertificatesAndCRLs(sp.getCertificatesAndCRLs("Collection", BC));
        
        bOut.reset();
        
        sigOut = gen.open(bOut, true);
    
        sigOut.write(TEST_MESSAGE.getBytes());
        
        sigOut.close();
    
        verifyEncodedData(bOut);

        //
        // look for the CRLs
        //
        Collection col = certsAndCrls.getCRLs(null);

        assertEquals(2, col.size());
        assertTrue(col.contains(_signCrl));
        assertTrue(col.contains(_origCrl));
    }

    public void testSHA1WithRSANonData()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        certList.add(_origCert);
        certList.add(_signCert);

        certList.add(_signCrl);
        certList.add(_origCrl);

        CertStore           certsAndCrls = CertStore.getInstance("Collection",
                                                       new CollectionCertStoreParameters(certList), BC);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, BC);

        gen.addCertificatesAndCRLs(certsAndCrls);

        OutputStream sigOut = gen.open(bOut, "1.2.3.4", true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        CMSSignedDataParser     sp = new CMSSignedDataParser(bOut.toByteArray());

        CMSTypedStream stream = sp.getSignedContent();

        assertEquals(new ASN1ObjectIdentifier("1.2.3.4"), stream.getContentType());

        stream.drain();

        //
        // compute expected content digest
        //
        MessageDigest md = MessageDigest.getInstance("SHA1", BC);

        verifySignatures(sp, md.digest(TEST_MESSAGE.getBytes()));
    }

    public void testSHA1AndMD5WithRSA()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        certList.add(_origCert);
        certList.add(_signCert);
    
        CertStore           certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), BC);
    
        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
    
        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, BC);
        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_MD5, BC);
        
        gen.addCertificatesAndCRLs(certs);
    
        OutputStream sigOut = gen.open(bOut);
    
        sigOut.write(TEST_MESSAGE.getBytes());
        
        sigOut.close();

        checkSigParseable(bOut.toByteArray());

        CMSSignedDataParser     sp = new CMSSignedDataParser(
                new CMSTypedStream(new ByteArrayInputStream(TEST_MESSAGE.getBytes())), bOut.toByteArray());
    
        sp.getSignedContent().drain();
        
        verifySignatures(sp);
    }
    
    public void testSHA1WithRSAEncapsulatedBufferedStream()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        certList.add(_origCert);
        certList.add(_signCert);

        CertStore           certs = CertStore.getInstance("Collection",
                               new CollectionCertStoreParameters(certList), BC);

        //
        // find unbuffered length
        //
        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, BC);

        gen.addCertificatesAndCRLs(certs);

        OutputStream sigOut = gen.open(bOut, true);
        
        for (int i = 0; i != 2000; i++)
        {
            sigOut.write(i & 0xff);
        }
        
        sigOut.close();
        
        CMSSignedDataParser     sp = new CMSSignedDataParser(bOut.toByteArray());

        sp.getSignedContent().drain();
        
        verifySignatures(sp);
        
        int unbufferedLength = bOut.toByteArray().length;
        
        //
        // find buffered length with buffered stream - should be equal
        //
        bOut = new ByteArrayOutputStream();

        gen = new CMSSignedDataStreamGenerator();
        
        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, BC);

        gen.addCertificatesAndCRLs(certs);

        sigOut = gen.open(bOut, true);

        BufferedOutputStream bfOut = new BufferedOutputStream(sigOut, 300);
        
        for (int i = 0; i != 2000; i++)
        {
            bfOut.write(i & 0xff);
        }
        
        bfOut.close();
        
        verifyEncodedData(bOut);
        
        assertTrue(bOut.toByteArray().length == unbufferedLength);
    }

    public void testSHA1WithRSAEncapsulatedBuffered()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        certList.add(_origCert);
        certList.add(_signCert);
    
        CertStore           certs = CertStore.getInstance("Collection",
                               new CollectionCertStoreParameters(certList), BC);
    
        //
        // find unbuffered length
        //
        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
    
        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, BC);
    
        gen.addCertificatesAndCRLs(certs);
    
        OutputStream sigOut = gen.open(bOut, true);
        
        for (int i = 0; i != 2000; i++)
        {
            sigOut.write(i & 0xff);
        }
        
        sigOut.close();
        
        CMSSignedDataParser     sp = new CMSSignedDataParser(bOut.toByteArray());
    
        sp.getSignedContent().drain();
        
        verifySignatures(sp);
        
        int unbufferedLength = bOut.toByteArray().length;
        
        //
        // find buffered length - buffer size less than default
        //
        bOut = new ByteArrayOutputStream();
    
        gen = new CMSSignedDataStreamGenerator();
        
        gen.setBufferSize(300);
        
        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, BC);
    
        gen.addCertificatesAndCRLs(certs);
    
        sigOut = gen.open(bOut, true);
    
        for (int i = 0; i != 2000; i++)
        {
            sigOut.write(i & 0xff);
        }
        
        sigOut.close();
        
        verifyEncodedData(bOut);

        assertTrue(bOut.toByteArray().length > unbufferedLength);
    }
    
    public void testSHA1WithRSAEncapsulated()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        certList.add(_origCert);
        certList.add(_signCert);

        CertStore           certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), BC);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, BC);

        gen.addCertificatesAndCRLs(certs);

        OutputStream sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());
        
        sigOut.close();
        
        CMSSignedDataParser     sp = new CMSSignedDataParser(bOut.toByteArray());

        sp.getSignedContent().drain();
        
        verifySignatures(sp);
        
        byte[] contentDigest = (byte[])gen.getGeneratedDigests().get(CMSSignedGenerator.DIGEST_SHA1);

        AttributeTable table = ((SignerInformation)sp.getSignerInfos().getSigners().iterator().next()).getSignedAttributes();
        Attribute hash = table.get(CMSAttributes.messageDigest);

        assertTrue(MessageDigest.isEqual(contentDigest, ((ASN1OctetString)hash.getAttrValues().getObjectAt(0)).getOctets()));

        //
        // try using existing signer
        //
        gen = new CMSSignedDataStreamGenerator();

        gen.addSigners(sp.getSignerInfos());
        
        gen.addCertificatesAndCRLs(sp.getCertificatesAndCRLs("Collection", BC));
        
        bOut.reset();
        
        sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());
        
        sigOut.close();

        CMSSignedData sd = new CMSSignedData(new CMSProcessableByteArray(TEST_MESSAGE.getBytes()), bOut.toByteArray());

        assertEquals(1, sd.getSignerInfos().getSigners().size());

        verifyEncodedData(bOut);
    }

    public void testSHA1WithRSAEncapsulatedSubjectKeyID()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        certList.add(_origCert);
        certList.add(_signCert);

        CertStore           certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), BC);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        gen.addSigner(_origKP.getPrivate(), CMSTestUtil.createSubjectKeyId(_origCert.getPublicKey()).getKeyIdentifier(), CMSSignedDataStreamGenerator.DIGEST_SHA1, BC);

        gen.addCertificatesAndCRLs(certs);

        OutputStream sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        CMSSignedDataParser     sp = new CMSSignedDataParser(bOut.toByteArray());

        sp.getSignedContent().drain();

        verifySignatures(sp);

        byte[] contentDigest = (byte[])gen.getGeneratedDigests().get(CMSSignedGenerator.DIGEST_SHA1);

        AttributeTable table = ((SignerInformation)sp.getSignerInfos().getSigners().iterator().next()).getSignedAttributes();
        Attribute hash = table.get(CMSAttributes.messageDigest);

        assertTrue(MessageDigest.isEqual(contentDigest, ((ASN1OctetString)hash.getAttrValues().getObjectAt(0)).getOctets()));

        //
        // try using existing signer
        //
        gen = new CMSSignedDataStreamGenerator();

        gen.addSigners(sp.getSignerInfos());

        gen.addCertificatesAndCRLs(sp.getCertificatesAndCRLs("Collection", BC));

        bOut.reset();

        sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        CMSSignedData sd = new CMSSignedData(new CMSProcessableByteArray(TEST_MESSAGE.getBytes()), bOut.toByteArray());

        assertEquals(1, sd.getSignerInfos().getSigners().size());

        verifyEncodedData(bOut);
    }

    public void testAttributeGenerators()
        throws Exception
    {
        final ASN1ObjectIdentifier dummyOid1 = new ASN1ObjectIdentifier("1.2.3");
        final ASN1ObjectIdentifier dummyOid2 = new ASN1ObjectIdentifier("1.2.3.4");
        List                      certList = new ArrayList();
        ByteArrayOutputStream     bOut = new ByteArrayOutputStream();

        certList.add(_origCert);
        certList.add(_signCert);

        CertStore           certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), BC);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        CMSAttributeTableGenerator signedGen = new DefaultSignedAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
            {
                Hashtable table = createStandardAttributeTable(parameters);

                DEROctetString val = new DEROctetString((byte[])parameters.get(CMSAttributeTableGenerator.DIGEST));
                Attribute attr = new Attribute(dummyOid1, new DERSet(val));

                table.put(attr.getAttrType(), attr);

                return new AttributeTable(table);
            }
        };

        CMSAttributeTableGenerator unsignedGen = new CMSAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
            {
                DEROctetString val = new DEROctetString((byte[])parameters.get(CMSAttributeTableGenerator.SIGNATURE));
                Attribute attr = new Attribute(dummyOid2, new DERSet(val));

                return new AttributeTable(new DERSet(attr));
            }
        };

        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, signedGen, unsignedGen, BC);

        gen.addCertificatesAndCRLs(certs);

        OutputStream sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        CMSSignedDataParser     sp = new CMSSignedDataParser(bOut.toByteArray());

        sp.getSignedContent().drain();

        verifySignatures(sp);

        //
        // check attributes
        //
        SignerInformationStore  signers = sp.getSignerInfos();

        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            checkAttribute(signer.getContentDigest(), signer.getSignedAttributes().get(dummyOid1));
            checkAttribute(signer.getSignature(), signer.getUnsignedAttributes().get(dummyOid2));
        }
    }

    private void checkAttribute(byte[] expected, Attribute attr)
    {
        DEROctetString      value = (DEROctetString)attr.getAttrValues().getObjectAt(0);

        assertEquals(new DEROctetString(expected), value);
    }

    public void testWithAttributeCertificate()
        throws Exception
    {
        List                  certList = new ArrayList();

        certList.add(_signCert);

        CertStore           certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), BC);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataGenerator.DIGEST_SHA1, BC);

        gen.addCertificatesAndCRLs(certs);

        X509AttributeCertificate attrCert = CMSTestUtil.getAttributeCertificate();

        X509Store store = X509Store.getInstance("AttributeCertificate/Collection",
                                    new X509CollectionStoreParameters(Collections.singleton(attrCert)), BC);

        gen.addAttributeCertificates(store);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        CMSSignedDataParser     sp = new CMSSignedDataParser(bOut.toByteArray());

        sp.getSignedContent().drain();

        assertEquals(4, sp.getVersion());

        store = sp.getAttributeCertificates("Collection", BC);

        Collection coll = store.getMatches(null);

        assertEquals(1, coll.size());

        assertTrue(coll.contains(attrCert));
    }

    public void testSignerStoreReplacement()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        byte[]                data = TEST_MESSAGE.getBytes();

        certList.add(_origCert);
        certList.add(_signCert);

        CertStore           certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), BC);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, BC);

        gen.addCertificatesAndCRLs(certs);

        OutputStream sigOut = gen.open(bOut, false);

        sigOut.write(data);

        sigOut.close();

        checkSigParseable(bOut.toByteArray());

        //
        // create new Signer
        //
        ByteArrayInputStream  original = new ByteArrayInputStream(bOut.toByteArray());

        bOut.reset();

        gen = new CMSSignedDataStreamGenerator();

        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA224, BC);

        gen.addCertificatesAndCRLs(certs);

        sigOut = gen.open(bOut);

        sigOut.write(data);

        sigOut.close();

        checkSigParseable(bOut.toByteArray());

        CMSSignedData sd = new CMSSignedData(bOut.toByteArray());

        //
        // replace signer
        //
        ByteArrayOutputStream newOut = new ByteArrayOutputStream();

        CMSSignedDataParser.replaceSigners(original, sd.getSignerInfos(), newOut);

        sd = new CMSSignedData(new CMSProcessableByteArray(data), newOut.toByteArray());
        SignerInformation signer = (SignerInformation)sd.getSignerInfos().getSigners().iterator().next();

        assertEquals(signer.getDigestAlgOID(), CMSSignedDataStreamGenerator.DIGEST_SHA224);

        CMSSignedDataParser sp = new CMSSignedDataParser(new CMSTypedStream(new ByteArrayInputStream(data)), newOut.toByteArray());

        sp.getSignedContent().drain();

        verifySignatures(sp);
    }

    public void testEncapsulatedSignerStoreReplacement()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        certList.add(_origCert);
        certList.add(_signCert);

        CertStore           certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), BC);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, BC);

        gen.addCertificatesAndCRLs(certs);

        OutputStream sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        //
        // create new Signer
        //
        ByteArrayInputStream  original = new ByteArrayInputStream(bOut.toByteArray());

        bOut.reset();

        gen = new CMSSignedDataStreamGenerator();

        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA224, BC);

        gen.addCertificatesAndCRLs(certs);

        sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        CMSSignedData sd = new CMSSignedData(bOut.toByteArray());

        //
        // replace signer
        //
        ByteArrayOutputStream newOut = new ByteArrayOutputStream();

        CMSSignedDataParser.replaceSigners(original, sd.getSignerInfos(), newOut);

        sd = new CMSSignedData(newOut.toByteArray());
        SignerInformation signer = (SignerInformation)sd.getSignerInfos().getSigners().iterator().next();

        assertEquals(signer.getDigestAlgOID(), CMSSignedDataStreamGenerator.DIGEST_SHA224);

        CMSSignedDataParser sp = new CMSSignedDataParser(newOut.toByteArray());

        sp.getSignedContent().drain();

        verifySignatures(sp);
    }

    public void testCertStoreReplacement()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        byte[]                data = TEST_MESSAGE.getBytes();

        certList.add(_origDsaCert);

        CertStore           certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), BC);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, BC);

        gen.addCertificatesAndCRLs(certs);

        OutputStream sigOut = gen.open(bOut);

        sigOut.write(data);

        sigOut.close();

        checkSigParseable(bOut.toByteArray());

        //
        // create new certstore with the right certificates
        //
        certList = new ArrayList();
        certList.add(_origCert);
        certList.add(_signCert);

        certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), BC);

        //
        // replace certs
        //
        ByteArrayInputStream original = new ByteArrayInputStream(bOut.toByteArray());
        ByteArrayOutputStream newOut = new ByteArrayOutputStream();

        CMSSignedDataParser.replaceCertificatesAndCRLs(original, certs, newOut);

        CMSSignedDataParser sp = new CMSSignedDataParser(new CMSTypedStream(new ByteArrayInputStream(data)), newOut.toByteArray());

        sp.getSignedContent().drain();

        verifySignatures(sp);
    }

    public void testEncapsulatedCertStoreReplacement()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        certList.add(_origDsaCert);

        CertStore           certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), BC);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, BC);

        gen.addCertificatesAndCRLs(certs);

        OutputStream sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        //
        // create new certstore with the right certificates
        //
        certList = new ArrayList();
        certList.add(_origCert);
        certList.add(_signCert);

        certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), BC);

        //
        // replace certs
        //
        ByteArrayInputStream original = new ByteArrayInputStream(bOut.toByteArray());
        ByteArrayOutputStream newOut = new ByteArrayOutputStream();

        CMSSignedDataParser.replaceCertificatesAndCRLs(original, certs, newOut);

        CMSSignedDataParser sp = new CMSSignedDataParser(newOut.toByteArray());

        sp.getSignedContent().drain();

        verifySignatures(sp);
    }

    public void testCertOrdering1()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        certList.add(_origCert);
        certList.add(_signCert);

        CertStore           certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), BC);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, BC);

        gen.addCertificatesAndCRLs(certs);

        OutputStream sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        CMSSignedDataParser sp = new CMSSignedDataParser(bOut.toByteArray());

        sp.getSignedContent().drain();
        certs = sp.getCertificatesAndCRLs("Collection", BC);
        Iterator it = certs.getCertificates(null).iterator();

        assertEquals(_origCert, it.next());
        assertEquals(_signCert, it.next());
    }

    public void testCertOrdering2()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        certList.add(_signCert);
        certList.add(_origCert);

        CertStore           certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), BC);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, BC);

        gen.addCertificatesAndCRLs(certs);

        OutputStream sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        CMSSignedDataParser sp = new CMSSignedDataParser(bOut.toByteArray());

        sp.getSignedContent().drain();
        certs = sp.getCertificatesAndCRLs("Collection", BC);
        Iterator it = certs.getCertificates(null).iterator();

        assertEquals(_signCert, it.next());
        assertEquals(_origCert, it.next());
    }

    public static Test suite()
        throws Exception
    {
        init();
        
        return new CMSTestSetup(new TestSuite(SignedDataStreamTest.class));
    }
}
