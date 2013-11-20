package org.bouncycastle.pqc.math.ntru.euclid.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class AllTests
    extends TestCase
{
    public static void main (String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }
    
    public static Test suite()
    {
        TestSuite suite = new TestSuite("NTRU Euclid Tests");
        
        suite.addTestSuite(BigIntEuclideanTest.class);
        suite.addTestSuite(IntEuclideanTest.class);

        return suite;
    }
}
