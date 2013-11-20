package org.bouncycastle.asn1.x9;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;

/**
 * ASN.1 def for Diffie-Hellman key exchange KeySpecificInfo structure. See
 * RFC 2631, or X9.42, for further details.
 */
public class KeySpecificInfo
    implements DEREncodable
{
    private DERObjectIdentifier algorithm;
    private ASN1OctetString      counter;

    public KeySpecificInfo(
        DERObjectIdentifier algorithm,
        ASN1OctetString     counter)
    {
        this.algorithm = algorithm;
        this.counter = counter;
    }

    public KeySpecificInfo(
        ASN1Sequence  seq)
    {
        Enumeration e = seq.getObjects();

        algorithm = (DERObjectIdentifier)e.nextElement();
        counter = (ASN1OctetString)e.nextElement();
    }

    public DERObjectIdentifier getAlgorithm()
    {
        return algorithm;
    }

    public ASN1OctetString getCounter()
    {
        return counter;
    }

    /**
     * <pre>
     *  KeySpecificInfo ::= SEQUENCE {
     *      algorithm OBJECT IDENTIFIER,
     *      counter OCTET STRING SIZE (4..4)
     *  }
     * </pre>
     */
    public DERObject getDERObject()
    {
        ASN1EncodableVector  seq = new ASN1EncodableVector();

        seq.add(algorithm);
        seq.add(counter);

        return new DERSequence(seq);
    }
}
