package org.bouncycastle.mail.smime.test;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.test.CMSTestUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEEnvelopedParser;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.mail.smime.util.FileBackedMimeBodyPart;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.encoders.Base64;

public class NewSMIMEEnvelopedTest 
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static String          _signDN;
    private static KeyPair         _signKP;

    private static String          _reciDN;
    private static KeyPair         _reciKP;
    private static X509Certificate _reciCert;

    private static String          _reciDN2;
    private static KeyPair         _reciKP2;
    private static X509Certificate _reciCert2;

    private static boolean         _initialised = false;

    private static final byte[] testMessage = Base64.decode(
        "TUlNRS1WZXJzaW9uOiAxLjANCkNvbnRlbnQtVHlwZTogbXVsdGlwYXJ0L21peGVkOyANCglib3VuZGFye" +
        "T0iLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzUwMTMyIg0KQ29udGVudC1MYW5ndWFnZTogZW" +
        "4NCkNvbnRlbnQtRGVzY3JpcHRpb246IEEgbWFpbCBmb2xsb3dpbmcgdGhlIERJUkVDVCBwcm9qZWN0IHN" +
        "wZWNpZmljYXRpb25zDQoNCi0tLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzUwMTMyDQpDb250" +
        "ZW50LVR5cGU6IHRleHQvcGxhaW47IG5hbWU9bnVsbDsgY2hhcnNldD11cy1hc2NpaQ0KQ29udGVudC1Uc" +
        "mFuc2Zlci1FbmNvZGluZzogN2JpdA0KQ29udGVudC1EaXNwb3NpdGlvbjogaW5saW5lOyBmaWxlbmFtZT" +
        "1udWxsDQoNCkNpYW8gZnJvbSB2aWVubmENCi0tLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzU" +
        "wMTMyLS0NCg==");

    private static void init()
        throws Exception
    {
        if (!_initialised)
        {
            _initialised = true;

            _signDN   = "O=Bouncy Castle, C=AU";
            _signKP   = CMSTestUtil.makeKeyPair();

            _reciDN   = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP   = CMSTestUtil.makeKeyPair();
            _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);

            _reciDN2   = "CN=Fred, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP2   = CMSTestUtil.makeKeyPair();
            _reciCert2 = CMSTestUtil.makeCertificate(_reciKP2, _reciDN2, _signKP, _signDN);
        }
    }

    public NewSMIMEEnvelopedTest(
        String name) 
    {
        super(name);
    }

    public static void main(
        String args[]) 
    {
        junit.textui.TestRunner.run(NewSMIMEEnvelopedTest.class);
    }

    public static Test suite() 
        throws Exception 
    {
        return new SMIMETestSetup(new TestSuite(NewSMIMEEnvelopedTest.class));
    }

    public void setUp()
        throws Exception
    {
        init();
    }

    private MimeMessage loadMessage(String name)
        throws MessagingException, FileNotFoundException
    {
        Session session = Session.getDefaultInstance(System.getProperties(), null);

        return new MimeMessage(session, getClass().getResourceAsStream(name));
    }

    private X509Certificate loadCert(String name)
        throws Exception
    {
        return (X509Certificate)CertificateFactory.getInstance("X.509", BC).generateCertificate(getClass().getResourceAsStream(name));
    }

    private PrivateKey loadKey(String name)
        throws Exception
    {
        return ((KeyPair)(new PEMReader(new InputStreamReader(getClass().getResourceAsStream(name)))).readObject()).getPrivate();
    }

    public void testHeaders()
        throws Exception
    {
        MimeBodyPart    msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");

        SMIMEEnvelopedGenerator  gen = new SMIMEEnvelopedGenerator();
          
        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));
         
        //
        // generate a MimeBodyPart object which encapsulates the content
        // we want encrypted.
        //

        MimeBodyPart mp = gen.generate(msg, new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());

        assertEquals("application/pkcs7-mime; name=\"smime.p7m\"; smime-type=enveloped-data", mp.getHeader("Content-Type")[0]);
        assertEquals("attachment; filename=\"smime.p7m\"", mp.getHeader("Content-Disposition")[0]);
        assertEquals("S/MIME Encrypted Message", mp.getHeader("Content-Description")[0]);
    }
    
    public void testDESEDE3Encrypted()
        throws Exception
    {
        MimeBodyPart  msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
        String        algorithm = SMIMEEnvelopedGenerator.DES_EDE3_CBC;
        
        verifyAlgorithm(algorithm, msg);
    }

    public void testParserDESEDE3Encrypted()
        throws Exception
    {
        MimeBodyPart  msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
        String        algorithm = SMIMEEnvelopedGenerator.DES_EDE3_CBC;
        
        verifyParserAlgorithm(algorithm, msg);
    }
    
    public void testIDEAEncrypted()
        throws Exception
    {
        if (isPresent("IDEA"))
        {
            MimeBodyPart  msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
            String        algorithm = SMIMEEnvelopedGenerator.IDEA_CBC;

            verifyAlgorithm(algorithm, msg);
        }
    }

    private boolean isPresent(String algorithm)
        throws Exception
    {
        try
        {
            Cipher.getInstance(algorithm, BC);

            return true;
        }
        catch (NoSuchAlgorithmException e)
        {
            return false;
        }
    }

    public void testRC2Encrypted()
        throws Exception
    {
        MimeBodyPart  msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
        String        algorithm = SMIMEEnvelopedGenerator.RC2_CBC;
        
        verifyAlgorithm(algorithm, msg);
    }

    public void testCASTEncrypted()
        throws Exception
    {
        MimeBodyPart  msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
        String        algorithm = SMIMEEnvelopedGenerator.CAST5_CBC;
        
        verifyAlgorithm(algorithm, msg);
    }
    
    public void testAES128Encrypted()
        throws Exception
    {
        MimeBodyPart  msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
        String        algorithm = SMIMEEnvelopedGenerator.AES128_CBC;
        
        verifyAlgorithm(algorithm, msg);
    }
    
    public void testAES192Encrypted()
        throws Exception
    {
        MimeBodyPart  msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
        String        algorithm = SMIMEEnvelopedGenerator.AES192_CBC;
        
        verifyAlgorithm(algorithm, msg);
    }
    
    public void testAES256Encrypted()
        throws Exception
    {
        MimeBodyPart  msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
        String        algorithm = SMIMEEnvelopedGenerator.AES256_CBC;
        
        verifyAlgorithm(algorithm, msg);
    }
    
    public void testSubKeyId()
        throws Exception
    {
        MimeBodyPart    msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");

        SMIMEEnvelopedGenerator   gen = new SMIMEEnvelopedGenerator();

        //
        // create a subject key id - this has to be done the same way as
        // it is done in the certificate associated with the private key
        //
        MessageDigest           dig = MessageDigest.getInstance("SHA1", BC);
        dig.update(SubjectPublicKeyInfo.getInstance(_reciCert.getPublicKey().getEncoded()).getPublicKeyData().getBytes());

          
        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(dig.digest(), _reciCert.getPublicKey()).setProvider(BC));
         
        //
        // generate a MimeBodyPart object which encapsulates the content
        // we want encrypted.
        //

        MimeBodyPart         mp = gen.generate(msg, new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());

        SMIMEEnveloped       m = new SMIMEEnveloped(mp);

        dig.update(SubjectPublicKeyInfo.getInstance(_reciCert.getPublicKey().getEncoded()).getPublicKeyData().getBytes());

        RecipientId          recId = new KeyTransRecipientId(dig.digest());

        RecipientInformationStore  recipients = m.getRecipientInfos();
        RecipientInformation       recipient = recipients.get(recId);

        MimeBodyPart    res = SMIMEUtil.toMimeBodyPart(recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC)));

        verifyMessageBytes(msg, res);
    }

    public void testDotNetEncMailMatch()
        throws Exception
    {
        MimeMessage message = loadMessage("dotnet_encrypted_mail.eml");

        SMIMEEnveloped env = new SMIMEEnveloped(message);

        RecipientInformationStore store = env.getRecipientInfos();

        assertNotNull(store.get(new JceKeyTransRecipientId(loadCert("dotnet_enc_cert.pem"))));
    }

    public void testAES128()
        throws Exception
    {
        MimeMessage message = loadMessage("test128.message");

        SMIMEEnveloped env = new SMIMEEnveloped(message);

        RecipientInformationStore store = env.getRecipientInfos();

        RecipientInformation recipInfo = store.get(new JceKeyTransRecipientId(loadCert("cert.pem")));

        assertNotNull(recipInfo);

        byte[] content = recipInfo.getContent(new JceKeyTransEnvelopedRecipient(loadKey("key.pem")));

        assertTrue(org.bouncycastle.util.Arrays.areEqual(testMessage, content));
    }

    public void testAES192()
        throws Exception
    {
        MimeMessage message = loadMessage("test192.message");

        SMIMEEnveloped env = new SMIMEEnveloped(message);

        RecipientInformationStore store = env.getRecipientInfos();

        RecipientInformation recipInfo = store.get(new JceKeyTransRecipientId(loadCert("cert.pem")));

        assertNotNull(recipInfo);

        byte[] content = recipInfo.getContent(new JceKeyTransEnvelopedRecipient(loadKey("key.pem")));

        assertTrue(org.bouncycastle.util.Arrays.areEqual(testMessage, content));
    }

    public void testAES256()
        throws Exception
    {
        MimeMessage message = loadMessage("test256.message");

        SMIMEEnveloped env = new SMIMEEnveloped(message);

        RecipientInformationStore store = env.getRecipientInfos();

        RecipientInformation recipInfo = store.get(new JceKeyTransRecipientId(loadCert("cert.pem")));

        assertNotNull(recipInfo);

        byte[] content = recipInfo.getContent(new JceKeyTransEnvelopedRecipient(loadKey("key.pem")));

        assertTrue(org.bouncycastle.util.Arrays.areEqual(testMessage, content));
    }

    public void testCapEncrypt()
        throws Exception
    {
        MimeBodyPart    msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");

        SMIMEEnvelopedGenerator   gen = new SMIMEEnvelopedGenerator();

        //
        // create a subject key id - this has to be done the same way as
        // it is done in the certificate associated with the private key
        //
        MessageDigest           dig = MessageDigest.getInstance("SHA1", BC);

        dig.update(_reciCert.getPublicKey().getEncoded());

        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(dig.digest(), _reciCert.getPublicKey()).setProvider(BC));
         
        //
        // generate a MimeBodyPart object which encapsulates the content
        // we want encrypted.
        //
        MimeBodyPart mp = gen.generate(msg, new JceCMSContentEncryptorBuilder(CMSAlgorithm.RC2_CBC, 40).setProvider(BC).build());

        SMIMEEnveloped       m = new SMIMEEnveloped(mp);

        dig.update(_reciCert.getPublicKey().getEncoded());

        RecipientId          recId = new KeyTransRecipientId(dig.digest());

        RecipientInformationStore  recipients = m.getRecipientInfos();
        RecipientInformation       recipient = recipients.get(recId);

        MimeBodyPart    res = SMIMEUtil.toMimeBodyPart(recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC)));

        verifyMessageBytes(msg, res);
    }
    
    public void testTwoRecipients()
        throws Exception
    {
        MimeBodyPart    _msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");

        SMIMEEnvelopedGenerator   gen = new SMIMEEnvelopedGenerator();

        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));
        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert2).setProvider(BC));
         
        //
        // generate a MimeBodyPart object which encapsulates the content
        // we want encrypted.
        //
        MimeBodyPart mp = gen.generate(_msg, new JceCMSContentEncryptorBuilder(CMSAlgorithm.RC2_CBC, 40).setProvider(BC).build());

        SMIMEEnvelopedParser       m = new SMIMEEnvelopedParser(mp);

        RecipientId                recId = getRecipientId(_reciCert2);

        RecipientInformationStore  recipients = m.getRecipientInfos();
        RecipientInformation       recipient = recipients.get(recId);
        
        FileBackedMimeBodyPart    res = SMIMEUtil.toMimeBodyPart(recipient.getContentStream(new JceKeyTransEnvelopedRecipient(_reciKP2.getPrivate()).setProvider(BC)));

        verifyMessageBytes(_msg, res);
        
        m = new SMIMEEnvelopedParser(mp);

        res.dispose();
        
        recId = getRecipientId(_reciCert);

        recipients = m.getRecipientInfos();
        recipient = recipients.get(recId);
 
        res = SMIMEUtil.toMimeBodyPart(recipient.getContentStream(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC)));

        verifyMessageBytes(_msg, res);
        
        res.dispose();
    }
    
    private void verifyAlgorithm(
        String algorithmOid,
        MimeBodyPart msg) 
        throws Exception
    {
        SMIMEEnvelopedGenerator  gen = new SMIMEEnvelopedGenerator();
          
        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));
         
        //
        // generate a MimeBodyPart object which encapsulates the content
        // we want encrypted.
        //

        MimeBodyPart   mp = gen.generate(msg, new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(algorithmOid)).setProvider(BC).build());
        SMIMEEnveloped m = new SMIMEEnveloped(mp);
        RecipientId    recId = getRecipientId(_reciCert);

        RecipientInformationStore  recipients = m.getRecipientInfos();
        RecipientInformation       recipient = recipients.get(recId);

        MimeBodyPart    res = SMIMEUtil.toMimeBodyPart(recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC)));

        verifyMessageBytes(msg, res);
    }
    
    private void verifyParserAlgorithm(
        String algorithmOid,
        MimeBodyPart msg) 
        throws Exception
    {
        SMIMEEnvelopedGenerator  gen = new SMIMEEnvelopedGenerator();

        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        //
        // generate a MimeBodyPart object which encapsulates the content
        // we want encrypted.
        //

        MimeBodyPart         mp = gen.generate(msg, new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(algorithmOid)).setProvider(BC).build());
        SMIMEEnvelopedParser m = new SMIMEEnvelopedParser(mp);
        RecipientId          recId = getRecipientId(_reciCert);

        RecipientInformationStore  recipients = m.getRecipientInfos();
        RecipientInformation       recipient = recipients.get(recId);

        MimeBodyPart    res = SMIMEUtil.toMimeBodyPart(recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC)));

        verifyMessageBytes(msg, res);
    }

    private RecipientId getRecipientId(
        X509Certificate cert) 
        throws IOException, CertificateEncodingException
    {
        RecipientId          recId = new JceKeyTransRecipientId(cert);

        return recId;
    }
    
    
    private void verifyMessageBytes(MimeBodyPart a, MimeBodyPart b) 
        throws IOException, MessagingException
    {
        ByteArrayOutputStream _baos = new ByteArrayOutputStream();
        a.writeTo(_baos);
        _baos.close();
        byte[] _msgBytes = _baos.toByteArray();
        _baos = new ByteArrayOutputStream();
        b.writeTo(_baos);
        _baos.close();
        byte[] _resBytes = _baos.toByteArray();
        
        assertEquals(true, Arrays.equals(_msgBytes, _resBytes));
    }
}
