package org.bouncycastle.mail.smime.test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.MessageDigest;
import org.bouncycastle.jce.cert.CertStore;
import org.bouncycastle.jce.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.ContentType;
import javax.mail.internet.InternetHeaders;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.cms.test.CMSTestUtil;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.mail.smime.SMIMESignedParser;
import org.bouncycastle.mail.smime.util.CRLFOutputStream;
import org.bouncycastle.mail.smime.util.FileBackedMimeBodyPart;
import org.bouncycastle.x509.X509AttributeCertificate;
import org.bouncycastle.x509.X509CollectionStoreParameters;
import org.bouncycastle.x509.X509Store;

public class SMIMESignedTest
    extends TestCase
{
    static MimeBodyPart    msg;
    
    static MimeBodyPart    msgR;
    static MimeBodyPart    msgRN;

    static String _origDN;
    static KeyPair _origKP;
    static X509Certificate _origCert;

    static String _signDN;
    static KeyPair _signKP;
    static X509Certificate _signCert;

    static String          reciDN;
    static KeyPair         reciKP;
    static X509Certificate reciCert;

    private static KeyPair         _signGostKP;
    private static X509Certificate _signGostCert;

    private static KeyPair         _signEcDsaKP;
    private static X509Certificate _signEcDsaCert;

    private static KeyPair         _signEcGostKP;
    private static X509Certificate _signEcGostCert;

    private static final JcaX509CertSelectorConverter selectorConverter = new JcaX509CertSelectorConverter();

    KeyPair         dsaSignKP;
    X509Certificate dsaSignCert;

    KeyPair         dsaOrigKP;
    X509Certificate dsaOrigCert;
    
    static
    {
        try
        {
            msg      = SMIMETestUtil.makeMimeBodyPart("Hello world!\n");
            
            msgR     = SMIMETestUtil.makeMimeBodyPart("Hello world!\r");
            msgRN    = SMIMETestUtil.makeMimeBodyPart("Hello world!\r\n");
            
            _origDN = "O=Bouncy Castle, C=AU";
            _origKP = CMSTestUtil.makeKeyPair();  
            _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _origKP, _origDN);
    
            _signDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
            _signKP = CMSTestUtil.makeKeyPair();
            _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _origKP, _origDN);

            _signGostKP   = CMSTestUtil.makeGostKeyPair();
            _signGostCert = CMSTestUtil.makeCertificate(_signGostKP, _signDN, _origKP, _origDN);

            _signEcDsaKP   = CMSTestUtil.makeEcDsaKeyPair();
            _signEcDsaCert = CMSTestUtil.makeCertificate(_signEcDsaKP, _signDN, _origKP, _origDN);

            _signEcGostKP = CMSTestUtil.makeEcGostKeyPair();
            _signEcGostCert = CMSTestUtil.makeCertificate(_signEcGostKP, _signDN, _origKP, _origDN);
        }
        catch (Exception e)
        {
            throw new RuntimeException("problem setting up signed test class: " + e);
        }
    }

    private static class LineOutputStream extends FilterOutputStream
    {
        private static byte newline[];

        public LineOutputStream(OutputStream outputstream)
        {
            super(outputstream);
        }

        public void writeln(String s)
            throws MessagingException
        {
            try
            {
                byte abyte0[] = getBytes(s);
                super.out.write(abyte0);
                super.out.write(newline);
            }
            catch(Exception exception)
            {
                throw new MessagingException("IOException", exception);
            }
        }

        public void writeln()
            throws MessagingException
        {
            try
            {
                super.out.write(newline);
            }
            catch(Exception exception)
            {
                throw new MessagingException("IOException", exception);
            }
        }

        static
        {
            newline = new byte[2];
            newline[0] = 13;
            newline[1] = 10;
        }

        private static byte[] getBytes(String s)
        {
            char ac[] = s.toCharArray();
            int i = ac.length;
            byte abyte0[] = new byte[i];
            int j = 0;

            while (j < i)
            {
                abyte0[j] = (byte)ac[j++];
            }

            return abyte0;
        }
    }

    /*
     *
     *  INFRASTRUCTURE
     *
     */

    public SMIMESignedTest(String name)
    {
        super(name);
    }

    public static void main(String args[]) 
    {
        junit.textui.TestRunner.run(SMIMESignedTest.class);
    }

    public static Test suite() 
    {
        return new SMIMETestSetup(new TestSuite(SMIMESignedTest.class));
    }
    
    public void testHeaders()
        throws Exception
    {
        MimeMultipart smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA1, msg, SMIMESignedGenerator.RFC3851_MICALGS);
        BodyPart      bp = smm.getBodyPart(1);

        assertEquals("application/pkcs7-signature; name=smime.p7s; smime-type=signed-data", bp.getHeader("Content-Type")[0]);
        assertEquals("attachment; filename=\"smime.p7s\"", bp.getHeader("Content-Disposition")[0]);
        assertEquals("S/MIME Cryptographic Signature", bp.getHeader("Content-Description")[0]);
    }

    public void testHeadersEncapsulated()
        throws Exception
    {
        List           certList = new ArrayList();

        certList.add(_signCert);
        certList.add(_origCert);

        CertStore           certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");

        ASN1EncodableVector signedAttrs = generateSignedAttributes();

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        gen.addSigner(_signKP.getPrivate(), _signCert, SMIMESignedGenerator.DIGEST_SHA1, new AttributeTable(signedAttrs), null);

        gen.addCertificatesAndCRLs(certs);

        MimeBodyPart res = gen.generateEncapsulated(msg, "BC");

        assertEquals("application/pkcs7-mime; name=smime.p7m; smime-type=signed-data", res.getHeader("Content-Type")[0]);
        assertEquals("attachment; filename=\"smime.p7m\"", res.getHeader("Content-Disposition")[0]);
        assertEquals("S/MIME Cryptographic Signed Data", res.getHeader("Content-Description")[0]);
    }

    public void testMultipartTextText()
        throws Exception
    {
        MimeBodyPart part1 = createTemplate("text/html", "7bit");
        MimeBodyPart part2 = createTemplate("text/xml", "7bit");

        multipartMixedTest(part1, part2);
    }

    public void testMultipartTextBinary()
        throws Exception
    {
        MimeBodyPart part1 = createTemplate("text/html", "7bit");
        MimeBodyPart part2 = createTemplate("text/xml", "binary");

        multipartMixedTest(part1, part2);
    }

    public void testMultipartBinaryText()
        throws Exception
    {
        MimeBodyPart part1 = createTemplate("text/xml", "binary");
        MimeBodyPart part2 = createTemplate("text/html", "7bit");

        multipartMixedTest(part1, part2);
    }

    public void testMultipartBinaryBinary()
        throws Exception
    {
        MimeBodyPart part1 = createTemplate("text/xml", "binary");
        MimeBodyPart part2 = createTemplate("text/html", "binary");

        multipartMixedTest(part1, part2);
    }

    public void testSHA1WithRSAPSS()
        throws Exception
    {
        rsaPSSTest(SMIMESignedGenerator.DIGEST_SHA1);
    }

    public void testSHA224WithRSAPSS()
        throws Exception
    {
        rsaPSSTest(SMIMESignedGenerator.DIGEST_SHA224);
    }

    public void testSHA256WithRSAPSS()
        throws Exception
    {
        rsaPSSTest(SMIMESignedGenerator.DIGEST_SHA256);
    }

    public void testSHA384WithRSAPSS()
        throws Exception
    {
        rsaPSSTest(SMIMESignedGenerator.DIGEST_SHA384);
    }

    public void multipartMixedTest(MimeBodyPart part1, MimeBodyPart part2)
        throws Exception
    {
        MimeMultipart mp = new MimeMultipart();

        mp.addBodyPart(part1);
        mp.addBodyPart(part2);

        MimeBodyPart m = new MimeBodyPart();

        m.setContent(mp);

        MimeMultipart smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA1, m, SMIMESignedGenerator.RFC3851_MICALGS);
        SMIMESigned   s = new SMIMESigned(smm);

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());

        AttributeTable attr = ((SignerInformation)s.getSignerInfos().getSigners().iterator().next()).getSignedAttributes();

        Attribute a = attr.get(CMSAttributes.messageDigest);
        byte[] contentDigest = ASN1OctetString.getInstance(a.getAttrValues().getObjectAt(0)).getOctets();

        mp = (MimeMultipart)m.getContent();
        ContentType contentType = new ContentType(mp.getContentType());
        String boundary = "--" + contentType.getParameter("boundary");

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        LineOutputStream lOut = new LineOutputStream(bOut);

        Enumeration headers = m.getAllHeaderLines();
        while (headers.hasMoreElements())
        {
            lOut.writeln((String)headers.nextElement());
        }

        lOut.writeln();      // CRLF separator

        lOut.writeln(boundary);
        writePart(mp.getBodyPart(0), bOut);
        lOut.writeln();       // CRLF terminator

        lOut.writeln(boundary);
        writePart(mp.getBodyPart(1), bOut);
        lOut.writeln();

        lOut.writeln(boundary + "--");

        MessageDigest dig = MessageDigest.getInstance("SHA1", "BC");

        assertTrue(Arrays.equals(contentDigest, dig.digest(bOut.toByteArray())));
    }

    private void writePart(BodyPart part, ByteArrayOutputStream bOut)
        throws MessagingException, IOException
    {
        if (part.getHeader("Content-Transfer-Encoding")[0].equals("binary"))
        {
            part.writeTo(bOut);
        }
        else
        {
            part.writeTo(new CRLFOutputStream(bOut));
        }
    }

    public void testSHA1WithRSA()
        throws Exception
    {
        MimeMultipart smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA1, msg, SMIMESignedGenerator.RFC3851_MICALGS);
        SMIMESigned   s = new SMIMESigned(smm);

        verifyMessageBytes(msg, s.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testSHA1WithRSAAddSigners()
        throws Exception
    {
        MimeMultipart smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA1, msg, SMIMESignedGenerator.RFC3851_MICALGS);
        SMIMESigned   s = new SMIMESigned(smm);

        List certList = new ArrayList();

        certList.add(_signCert);
        certList.add(_origCert);

        CertStore certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        gen.addSigners(s.getSignerInfos());

        gen.addCertificatesAndCRLs(certs);

        SMIMESigned newS =  new SMIMESigned(gen.generate(msg, "BC"));

        verifyMessageBytes(msg, newS.getContent());

        verifySigners(newS.getCertificatesAndCRLs("Collection", "BC"), newS.getSignerInfos());
    }

    public void testMD5WithRSAAddSignersSHA1()
        throws Exception
    {
        MimeMultipart smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA1, msg, SMIMESignedGenerator.RFC3851_MICALGS);
        SMIMESigned   s = new SMIMESigned(smm);

        List certList = new ArrayList();

        certList.add(_signCert);
        certList.add(_origCert);

        CertStore certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        gen.addSigner(_signKP.getPrivate(), _signCert, SMIMESignedGenerator.DIGEST_MD5);
        
        gen.addSigners(s.getSignerInfos());

        gen.addCertificatesAndCRLs(certs);

        smm = gen.generate(msg, "BC");

        SMIMESigned newS =  new SMIMESigned(gen.generate(msg, "BC"));

        verifyMessageBytes(msg, newS.getContent());

        verifySigners(newS.getCertificatesAndCRLs("Collection", "BC"), newS.getSignerInfos());

        assertEquals("\"md5,sha-1\"", getMicAlg(smm));
    }

    public void testSHA1WithRSACanonicalization()
        throws Exception
    {
        Date          testTime = new Date();
        MimeMultipart smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA1, msg, testTime, SMIMESignedGenerator.RFC3851_MICALGS);
        
        byte[] sig1 = getEncodedStream(smm);
    
        smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA1, msgR, testTime, SMIMESignedGenerator.RFC3851_MICALGS);

        byte[] sig2 = getEncodedStream(smm);

        assertTrue(Arrays.equals(sig1, sig2));
        
        smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA1, msgRN, testTime, SMIMESignedGenerator.RFC3851_MICALGS);

        byte[] sig3 = getEncodedStream(smm);

        assertTrue(Arrays.equals(sig1, sig3));
    }

    private byte[] getEncodedStream(MimeMultipart smm) 
        throws IOException, MessagingException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        smm.getBodyPart(1).writeTo(bOut);

        return bOut.toByteArray();
    }
    
    public void testSHA1WithRSAEncapsulated()
        throws Exception
    {
        MimeBodyPart res = generateEncapsulatedRsa(SMIMESignedGenerator.DIGEST_SHA1, msg);
        SMIMESigned  s = new SMIMESigned(res);

        verifyMessageBytes(msg, s.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }
    
    public void testSHA1WithRSAEncapsulatedParser()
        throws Exception
    {
        MimeBodyPart res = generateEncapsulatedRsa(SMIMESignedGenerator.DIGEST_SHA1, msg);       
        SMIMESignedParser s = new SMIMESignedParser(res);

        FileBackedMimeBodyPart content = (FileBackedMimeBodyPart)s.getContent();
        
        verifyMessageBytes(msg, content);
    
        content.dispose();
        
        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
        
        s.close();
    }
    
    public void testSHA1WithRSAEncapsulatedParserAndFile()
        throws Exception
    {
        File         tmp = File.createTempFile("bcTest", ".mime");
        MimeBodyPart res = generateEncapsulatedRsa(SMIMESignedGenerator.DIGEST_SHA1, msg);       
        SMIMESignedParser s = new SMIMESignedParser(res, tmp);
        FileBackedMimeBodyPart content = (FileBackedMimeBodyPart)s.getContent();
    
        verifyMessageBytes(msg, s.getContent());
    
        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
        
        assertTrue(tmp.exists());
        
        s.close();
        
        content.dispose();
        
        assertFalse(tmp.exists());
    }

    public void testMD5WithRSA()
        throws Exception
    {
        MimeMultipart smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_MD5, msg, SMIMESignedGenerator.RFC3851_MICALGS);
        SMIMESigned   s = new  SMIMESigned(smm);

        assertEquals("md5", getMicAlg(smm));
        assertEquals(getDigestOid(s.getSignerInfos()), PKCSObjectIdentifiers.md5.toString());
        
        verifyMessageBytes(msg, s.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testSHA224WithRSA()
        throws Exception
    {
        MimeMultipart smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA224, msg, SMIMESignedGenerator.RFC3851_MICALGS);
        SMIMESigned   s = new  SMIMESigned(smm);

        assertEquals("sha224", getMicAlg(smm));
        assertEquals(getDigestOid(s.getSignerInfos()), NISTObjectIdentifiers.id_sha224.toString());
        
        verifyMessageBytes(msg, s.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testSHA256WithRSA()
        throws Exception
    {
        MimeMultipart smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA256, msg, SMIMESignedGenerator.RFC3851_MICALGS);
        SMIMESigned   s = new  SMIMESigned(smm);

        assertEquals("sha256", getMicAlg(smm));
        assertEquals(getDigestOid(s.getSignerInfos()), NISTObjectIdentifiers.id_sha256.toString());

        verifyMessageBytes(msg, s.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testSHA384WithRSA()
        throws Exception
    {
        MimeMultipart smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA384, msg, SMIMESignedGenerator.RFC3851_MICALGS);
        SMIMESigned   s = new  SMIMESigned(smm);

        assertEquals("sha384", getMicAlg(smm));
        assertEquals(getDigestOid(s.getSignerInfos()), NISTObjectIdentifiers.id_sha384.toString());

        verifyMessageBytes(msg, s.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testSHA512WithRSA()
        throws Exception
    {
        MimeMultipart smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA512, msg, SMIMESignedGenerator.RFC3851_MICALGS);
        SMIMESigned   s = new  SMIMESigned(smm);

        assertEquals("sha512", getMicAlg(smm));
        assertEquals(getDigestOid(s.getSignerInfos()), NISTObjectIdentifiers.id_sha512.toString());

        verifyMessageBytes(msg, s.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testRIPEMD160WithRSA()
        throws Exception
    {
        MimeMultipart smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_RIPEMD160, msg, SMIMESignedGenerator.RFC3851_MICALGS);
        SMIMESigned   s = new  SMIMESigned(smm);

        assertEquals("unknown", getMicAlg(smm));
        assertEquals(getDigestOid(s.getSignerInfos()), TeleTrusTObjectIdentifiers.ripemd160.toString());

        verifyMessageBytes(msg, s.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testGOST3411WithGOST3410()
        throws Exception
    {
        MimeMultipart smm = generateMultiPartGost(msg);
        SMIMESigned   s = new  SMIMESigned(smm);

        assertEquals("gostr3411-94", getMicAlg(smm));
        assertEquals(getDigestOid(s.getSignerInfos()), CryptoProObjectIdentifiers.gostR3411.getId());

        verifyMessageBytes(msg, s.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testGOST3411WithECGOST3410()
        throws Exception
    {
        MimeMultipart smm = generateMultiPartECGost(msg);
        SMIMESigned   s = new  SMIMESigned(smm);

        assertEquals("gostr3411-94", getMicAlg(smm));
        assertEquals(getDigestOid(s.getSignerInfos()), CryptoProObjectIdentifiers.gostR3411.getId());

        verifyMessageBytes(msg, s.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testSHA224WithRSAParser()
        throws Exception
    {
        MimeMultipart     smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA224, msg, SMIMESignedGenerator.RFC3851_MICALGS);
        SMIMESignedParser s = new SMIMESignedParser(smm);
        CertStore         certs = s.getCertificatesAndCRLs("Collection", "BC");
        
        assertEquals(getDigestOid(s.getSignerInfos()), NISTObjectIdentifiers.id_sha224.toString());
        
        verifyMessageBytes(msg, s.getContent());
    
        verifySigners(certs, s.getSignerInfos());
    }
    
    public void testSHA224WithRSAParserEncryptedWithDES()
        throws Exception
    {
        List certList = new ArrayList();
        
        certList.add(_signCert);
        certList.add(_origCert);
    
        CertStore certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");
    
        ASN1EncodableVector signedAttrs = generateSignedAttributes();
    
        SMIMESignedGenerator gen = new SMIMESignedGenerator();
    
        gen.addSigner(_signKP.getPrivate(), _signCert, SMIMESignedGenerator.DIGEST_SHA224, new AttributeTable(signedAttrs), null);
        gen.addCertificatesAndCRLs(certs);

        MimeMultipart     smm = gen.generate(msg, "BC");
        SMIMESignedParser s = new SMIMESignedParser(smm);
        
        certs = s.getCertificatesAndCRLs("Collection", "BC");
        
        assertEquals(getDigestOid(s.getSignerInfos()), NISTObjectIdentifiers.id_sha224.toString());
        
        verifyMessageBytes(msg, s.getContent());
    
        verifySigners(certs, s.getSignerInfos());
    }
    
    public void testSHA1withDSA()
        throws Exception
    {
        dsaSignKP   = CMSTestUtil.makeDsaKeyPair();
        dsaSignCert = CMSTestUtil.makeCertificate(dsaSignKP, _origDN, dsaSignKP, _origDN);

        dsaOrigKP   = CMSTestUtil.makeDsaKeyPair();
        dsaOrigCert = CMSTestUtil.makeCertificate(dsaOrigKP, _signDN, dsaSignKP, _origDN);

        List           certList = new ArrayList();

        certList.add(dsaOrigCert);
        certList.add(dsaSignCert);

        CertStore      certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        gen.addSigner(dsaOrigKP.getPrivate(), dsaOrigCert, SMIMESignedGenerator.DIGEST_SHA1);
        gen.addCertificatesAndCRLs(certs);


        MimeMultipart smm = gen.generate(msg, "BC");
        SMIMESigned   s = new  SMIMESigned(smm);

        verifyMessageBytes(msg, s.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }
    
    public void testSHA256WithRSABinary()
        throws Exception
    {
        MimeBodyPart  msg = generateBinaryPart();
        MimeMultipart smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA256, msg, SMIMESignedGenerator.RFC3851_MICALGS);
        SMIMESigned   s = new  SMIMESigned(smm);

        verifyMessageBytes(msg, s.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testSHA256WithRSABinaryWithParser()
        throws Exception
    {
        MimeBodyPart      msg = generateBinaryPart();
        MimeMultipart     smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA256, msg, SMIMESignedGenerator.RFC3851_MICALGS);
        SMIMESignedParser s = new SMIMESignedParser(smm);
    
        verifyMessageBytes(msg, s.getContent());
    
        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testWithAttributeCertificate()
        throws Exception
    {
        List certList = new ArrayList();

        certList.add(_signCert);
        certList.add(_origCert);

        CertStore certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");

        ASN1EncodableVector signedAttrs = generateSignedAttributes();

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        gen.addSigner(_signKP.getPrivate(), _signCert, SMIMESignedGenerator.DIGEST_SHA256, new AttributeTable(signedAttrs), null);

        gen.addCertificatesAndCRLs(certs);

        X509AttributeCertificate attrCert = CMSTestUtil.getAttributeCertificate();

        X509Store store = X509Store.getInstance("AttributeCertificate/Collection",
                                    new X509CollectionStoreParameters(Collections.singleton(attrCert)), "BC");

        gen.addAttributeCertificates(store);

        SMIMESigned s = new SMIMESigned(gen.generateEncapsulated(msg, "BC"));

        verifyMessageBytes(msg, s.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());

        X509Store attrCerts = s.getAttributeCertificates("Collection", "BC");

        assertTrue(attrCerts.getMatches(null).contains(attrCert));
    }

    private void rsaPSSTest(String digestOID)
        throws Exception
    {
        MimeMultipart     smm = generateMultiPartRsaPSS(digestOID, msg, null);
        SMIMESignedParser s = new SMIMESignedParser(smm);
        CertStore         certs = s.getCertificatesAndCRLs("Collection", "BC");

        assertEquals(getDigestOid(s.getSignerInfos()), digestOID);

        verifyMessageBytes(msg, s.getContent());

        verifySigners(certs, s.getSignerInfos());
    }

    private MimeBodyPart generateBinaryPart() throws MessagingException
    {
        byte[] content = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 10, 11, 12, 13, 14, 10, 10, 15, 16 };   
        InternetHeaders ih = new InternetHeaders();
        
        ih.setHeader("Content-Transfer-Encoding", "binary");
        return new MimeBodyPart(ih, content);
    }
    
    private MimeMultipart generateMultiPartRsa(
        String digestOid, 
        MimeBodyPart msg,
        Date         signingTime,
        Map          micalgs)
        throws Exception
    {
        List certList = new ArrayList();
    
        certList.add(_signCert);
        certList.add(_origCert);
    
        CertStore certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");
    
        ASN1EncodableVector signedAttrs = generateSignedAttributes();
        
        if (signingTime != null)
        {
            signedAttrs.add(new Attribute(CMSAttributes.signingTime, new DERSet(new Time(signingTime))));
        }
    
        SMIMESignedGenerator gen = new SMIMESignedGenerator(micalgs);
    
        gen.addSigner(_signKP.getPrivate(), _signCert, digestOid, new AttributeTable(signedAttrs), null);
        gen.addCertificatesAndCRLs(certs);

        return gen.generate(msg, "BC");
    }

    private MimeMultipart generateMultiPartRsaPSS(
        String digestOid,
        MimeBodyPart msg,
        Date         signingTime)
        throws Exception
    {
        List certList = new ArrayList();

        certList.add(_signCert);
        certList.add(_origCert);

        CertStore certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");

        ASN1EncodableVector signedAttrs = generateSignedAttributes();

        if (signingTime != null)
        {
            signedAttrs.add(new Attribute(CMSAttributes.signingTime, new DERSet(new Time(signingTime))));
        }

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        gen.addSigner(_signKP.getPrivate(), _signCert, SMIMESignedGenerator.ENCRYPTION_RSA_PSS, digestOid, new AttributeTable(signedAttrs), null);
        gen.addCertificatesAndCRLs(certs);

        return gen.generate(msg, "BC");
    }

    private MimeMultipart generateMultiPartGost(
        MimeBodyPart msg)
        throws Exception
    {
        List certList = new ArrayList();

        certList.add(_signCert);
        certList.add(_signGostCert);

        CertStore certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        gen.addSigner(_signGostKP.getPrivate(), _signGostCert, SMIMESignedGenerator.DIGEST_GOST3411);
        gen.addCertificatesAndCRLs(certs);

        return gen.generate(msg, "BC");
    }

    private MimeMultipart generateMultiPartECGost(
        MimeBodyPart msg)
        throws Exception
    {
        List certList = new ArrayList();

        certList.add(_signCert);
        certList.add(_signEcGostCert);

        CertStore certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        gen.addSigner(_signEcGostKP.getPrivate(), _signEcGostCert, SMIMESignedGenerator.DIGEST_GOST3411);
        gen.addCertificatesAndCRLs(certs);

        return gen.generate(msg, "BC");
    }

    private MimeMultipart generateMultiPartRsa(String digestOid, MimeBodyPart msg, Map micalgs)
        throws Exception
    {
        return generateMultiPartRsa(digestOid, msg, null, micalgs);
    }
    
    private MimeBodyPart generateEncapsulatedRsa(String digestOid, MimeBodyPart msg) 
        throws Exception
    {
        List certList = new ArrayList();
    
        certList.add(_signCert);
        certList.add(_origCert);
    
        CertStore certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");
    
        ASN1EncodableVector signedAttrs = generateSignedAttributes();
    
        SMIMESignedGenerator gen = new SMIMESignedGenerator();
    
        gen.addSigner(_signKP.getPrivate(), _signCert, digestOid, new AttributeTable(signedAttrs), null);
        gen.addCertificatesAndCRLs(certs);
    
        return gen.generateEncapsulated(msg, "BC");
    }
    
    public void testCertificateManagement()
        throws Exception
    {
        List           certList = new ArrayList();

        certList.add(_signCert);
        certList.add(_origCert);

        CertStore           certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        gen.addCertificatesAndCRLs(certs);
        
        MimeBodyPart smm = gen.generateCertificateManagement("BC");
        
        SMIMESigned s = new  SMIMESigned(smm);

        certs = s.getCertificatesAndCRLs("Collection", "BC");

        assertEquals(2, certs.getCertificates(null).size());
    }

    public void testMimeMultipart()
        throws Exception
    {
        MimeBodyPart m = createMultipartMessage();

        List certList = new ArrayList();

        certList.add(_signCert);
        certList.add(_origCert);

        CertStore certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");

        ASN1EncodableVector signedAttrs = generateSignedAttributes();

        SMIMESignedGenerator gen = new SMIMESignedGenerator("binary");

        gen.addSigner(_signKP.getPrivate(), _signCert, SMIMESignedGenerator.DIGEST_SHA1, new AttributeTable(signedAttrs), null);
        gen.addCertificatesAndCRLs(certs);

        MimeMultipart mm = gen.generate(m, "BC");

        SMIMESigned s = new SMIMESigned(mm);

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());

        byte[] contentDigest = (byte[])gen.getGeneratedDigests().get(SMIMESignedGenerator.DIGEST_SHA1);

        AttributeTable table = ((SignerInformation)s.getSignerInfos().getSigners().iterator().next()).getSignedAttributes();
        Attribute hash = table.get(CMSAttributes.messageDigest);

        assertTrue(MessageDigest.isEqual(contentDigest, ((ASN1OctetString)hash.getAttrValues().getObjectAt(0)).getOctets()));
    }

    public void testMimeMultipartBinaryReader()
        throws Exception
    {
        MimeBodyPart m = createMultipartMessage();

        List certList = new ArrayList();

        certList.add(_signCert);
        certList.add(_origCert);

        CertStore certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");

        ASN1EncodableVector signedAttrs = generateSignedAttributes();

        SMIMESignedGenerator gen = new SMIMESignedGenerator("binary");

        gen.addSigner(_signKP.getPrivate(), _signCert, SMIMESignedGenerator.DIGEST_SHA1, new AttributeTable(signedAttrs), null);
        gen.addCertificatesAndCRLs(certs);

        MimeMultipart mm = gen.generate(m, "BC");

        SMIMESigned s = new SMIMESigned(mm, "binary");

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testMimeMultipartBinaryParser()
        throws Exception
    {
        MimeBodyPart m = createMultipartMessage();

        List certList = new ArrayList();

        certList.add(_signCert);
        certList.add(_origCert);

        CertStore certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");

        ASN1EncodableVector signedAttrs = generateSignedAttributes();

        SMIMESignedGenerator gen = new SMIMESignedGenerator("binary");

        gen.addSigner(_signKP.getPrivate(), _signCert, SMIMESignedGenerator.DIGEST_SHA1, new AttributeTable(signedAttrs), null);
        gen.addCertificatesAndCRLs(certs);

        MimeMultipart mm = gen.generate(m, "BC");

        SMIMESignedParser s = new SMIMESignedParser(mm, "binary");

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testMimeMultipartBinaryParserGetMimeContent()
        throws Exception
    {
        MimeBodyPart m = createMultipartMessage();

        List certList = new ArrayList();

        certList.add(_signCert);
        certList.add(_origCert);

        CertStore certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");

        ASN1EncodableVector signedAttrs = generateSignedAttributes();

        SMIMESignedGenerator gen = new SMIMESignedGenerator("binary");

        gen.addSigner(_signKP.getPrivate(), _signCert, SMIMESignedGenerator.DIGEST_SHA1, new AttributeTable(signedAttrs), null);
        gen.addCertificatesAndCRLs(certs);

        MimeMultipart mm = gen.generate(m, "BC");

        SMIMESignedParser s = new SMIMESignedParser(mm, "binary");

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());

        MimeMessage bp = s.getContentAsMimeMessage(Session.getDefaultInstance(new Properties()));
    }

    private MimeBodyPart createMultipartMessage()
        throws MessagingException
    {
        MimeBodyPart    msg1 = new MimeBodyPart();

        msg1.setText("Hello part 1!\n");

        MimeBodyPart    msg2 = new MimeBodyPart();

        msg2.setText("Hello part 2!\n");

        MimeMultipart mp = new MimeMultipart();

        mp.addBodyPart(msg1);
        mp.addBodyPart(msg2);

        MimeBodyPart m = new MimeBodyPart();

        m.setContent(mp);

        return m;
    }

    public void testQuotable()
        throws Exception
    {
        MimeMessage message = loadMessage("quotable.message");
        
        SMIMESigned s = new SMIMESigned((MimeMultipart)message.getContent());
        
        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }
    
    public void testQuotableParser()
        throws Exception
    {
        MimeMessage message = loadMessage("quotable.message");
        
        SMIMESignedParser s = new SMIMESignedParser((MimeMultipart)message.getContent());
        
        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testEmbeddedMulti()
        throws Exception
    {
        MimeMessage message = loadMessage("embeddedmulti.message");

        SMIMESigned s = new SMIMESigned((MimeMultipart)message.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testEmbeddedMultiParser()
        throws Exception
    {
        MimeMessage message = loadMessage("embeddedmulti.message");

        SMIMESignedParser s = new SMIMESignedParser((MimeMultipart)message.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testMultiAlternative()
        throws Exception
    {
        MimeMessage message = loadMessage("multi-alternative.eml");

        SMIMESigned s = new SMIMESigned((MimeMultipart)message.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testExtraNlInPostamble()
        throws Exception
    {
        MimeMessage message = loadMessage("extra-nl.eml");

        SMIMESigned s = new SMIMESigned((MimeMultipart)message.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testSignAttachmentOnly()
        throws Exception
    {
        MimeMessage m = loadMessage("attachonly.eml");

        List certList = new ArrayList();

        certList.add(_signCert);
        certList.add(_origCert);

        CertStore certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");

        ASN1EncodableVector signedAttrs = generateSignedAttributes();

        SMIMESignedGenerator gen = new SMIMESignedGenerator("binary");

        gen.addSigner(_signKP.getPrivate(), _signCert, SMIMESignedGenerator.DIGEST_SHA1, new AttributeTable(signedAttrs), null);
        gen.addCertificatesAndCRLs(certs);

        MimeMultipart mm = gen.generate(m, "BC");

        SMIMESigned s = new SMIMESigned(mm);

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());

        SMIMESignedParser sp = new SMIMESignedParser(mm);

        verifySigners(sp.getCertificatesAndCRLs("Collection", "BC"), sp.getSignerInfos());
    }

    public void testMultiAlternativeParser()
        throws Exception
    {
        MimeMessage message = loadMessage("multi-alternative.eml");

        SMIMESignedParser s = new SMIMESignedParser((MimeMultipart)message.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testBasicAS2()
        throws Exception
    {
        MimeMessage message = loadMessage("basicAS2.message");

        SMIMESigned s = new SMIMESigned((MimeMultipart)message.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testBasicAS2Parser()
        throws Exception
    {
        MimeMessage message = loadMessage("basicAS2.message");

        SMIMESignedParser s = new SMIMESignedParser((MimeMultipart)message.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    private String getDigestOid(SignerInformationStore s)
    {
        return ((SignerInformation)s.getSigners().iterator().next()).getDigestAlgOID();
    }
    
    private void verifySigners(CertStore certs, SignerInformationStore signers) 
        throws Exception
    {
        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();
    
        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certs.getCertificates(selectorConverter.getCertSelector(signer.getSID()));
    
            Iterator        certIt = certCollection.iterator();
            X509Certificate cert = (X509Certificate)certIt.next();
    
            assertEquals(true, signer.verify(cert, "BC"));
        }
    }
    
    private void verifyMessageBytes(MimeBodyPart a, MimeBodyPart b) 
        throws Exception
    {
        ByteArrayOutputStream bOut1 = new ByteArrayOutputStream();
        
        a.writeTo(bOut1);
        bOut1.close();
        
        ByteArrayOutputStream bOut2 = new ByteArrayOutputStream();
        
        b.writeTo(bOut2);
        bOut2.close();
        
        assertEquals(true, Arrays.equals(bOut1.toByteArray(), bOut2.toByteArray()));
    }
    
    private ASN1EncodableVector generateSignedAttributes()
    {
        ASN1EncodableVector         signedAttrs = new ASN1EncodableVector();
        SMIMECapabilityVector       caps = new SMIMECapabilityVector();

        caps.addCapability(SMIMECapability.dES_EDE3_CBC);
        caps.addCapability(SMIMECapability.rC2_CBC, 128);
        caps.addCapability(SMIMECapability.dES_CBC);

        signedAttrs.add(new SMIMECapabilitiesAttribute(caps));
        
        return signedAttrs;
    }
    
    private MimeMessage loadMessage(String name)
        throws MessagingException, FileNotFoundException
    {
        Session session = Session.getDefaultInstance(System.getProperties(), null);

        return new MimeMessage(session, getClass().getResourceAsStream(name));
    }

    private MimeBodyPart createTemplate(String contentType, String contentTransferEncoding)
        throws UnsupportedEncodingException, MessagingException
    {
        byte[] content = "<?xml version=\"1.0\"?>\n<INVOICE_CENTER>\n  <CONTENT_FRAME>\n</CONTENT_FRAME>\n</INVOICE_CENTER>\n".getBytes("US-ASCII");

        InternetHeaders ih = new InternetHeaders();
        ih.setHeader("Content-Type", contentType);
        ih.setHeader("Content-Transfer-Encoding", contentTransferEncoding);

        return new MimeBodyPart(ih, content);
    }

    private String getMicAlg(MimeMultipart mm)
    {
        String contentType = mm.getContentType();
        String micAlg = contentType.substring(contentType.indexOf("micalg=") + 7);

        return micAlg.substring(0, micAlg.indexOf(';'));
    }
}
