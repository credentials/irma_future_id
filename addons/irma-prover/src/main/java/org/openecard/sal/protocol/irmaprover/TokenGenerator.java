
/** 
* Simple class to interface the user side of ABC4Trust
* into the IRMA add-on of Future ID.
*/

package org.openecard.sal.protocol.irmaprover;

import java.io.File;
import java.util.List;
import java.io.FileWriter;
import java.io.StringWriter;
import java.lang.Process;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.Charset;

public class TokenGenerator {

  private String serialPolicy;
  private String generationScript;
  private String generationScriptPath;
   
  public TokenGenerator(String serialPolicy, String generationScript, String generationScriptPath) {
   this.serialPolicy = serialPolicy;
   this.generationScript = generationScript;
   this.generationScriptPath = generationScriptPath;
  }
  
  public void generatePolicyToken(String presentationPolicyDest) {

    StringWriter sw = new StringWriter();
    sw.write(this.serialPolicy);
 
    try {

     FileWriter fw = new FileWriter(presentationPolicyDest);
     fw.write(sw.toString());
     fw.close();

     Process pr = Runtime.getRuntime().exec(this.generationScript, null, new File(this.generationScriptPath));

    } catch (Exception e) {
     e.printStackTrace();
    }
  }

  public void selfTest(String verificationScript, String generationScriptPath) {

    try {

     Process pr = Runtime.getRuntime().exec(verificationScript, null, new File(generationScriptPath));

    } catch (Exception e) {
     e.printStackTrace();
    }
  }

  public String getPresentationToken(String pathToPresentationToken) {
   byte[] encoded = null;
  
   try {
    encoded = Files.readAllBytes(Paths.get(pathToPresentationToken));
   } catch(Exception e) {
     e.printStackTrace();
   }
   
   return new String(encoded,  Charset.defaultCharset());
  }

  public static void main( String[] args ) {
   String testPolicy = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><PresentationPolicyAlternatives xmlns=\"http://abc4trust.eu/wp2/abcschemav1.0\" Version=\"1.0\"><PresentationPolicy PolicyUID=\"http://MyFavoriteSoccerTeam/policies/match/842/vip\"><Message><Nonce>2Hkb+I0tbst/dA==</Nonce><TokenGeneratorlicationData>        MyFavoriteSoccerTeam vs. OtherTeam      </TokenGeneratorlicationData></Message><Credential Alias=\"#ticket\"><CredentialSpecAlternatives><CredentialSpecUID>http://MyFavoriteSoccerTeam/tickets/vip</CredentialSpecUID></CredentialSpecAlternatives><IssuerAlternatives><IssuerParametersUID RevocationInformationUID=\"urn:abc4trust:1.0:revocation:information/4hjqwl0htcw1hbc\">http://ticketcompany/MyFavoriteSoccerTeam/issuance:idemix</IssuerParametersUID></IssuerAlternatives><DisclosedAttribute AttributeType=\"City\" DataHandlingPolicy=\"http://www.sweetdreamsuites.com/policies/creditcards\"/><DisclosedAttribute AttributeType=\"State\" DataHandlingPolicy=\"http://www.sweetdreamsuites.com/policies/creditcards\"/></Credential><AttributePredicate Function=\"urn:oasis:names:tc:xacml:1.0:function:date-equal\"><Attribute CredentialAlias=\"#ticket\" AttributeType=\"IDValidFrom\"/><ConstantValue xmlns:abc=\"http://abc4trust.eu/wp2/abcschemav1.0\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">2002-11-01Z</ConstantValue></AttributePredicate></PresentationPolicy></PresentationPolicyAlternatives>";
   String testGenerationScript = "/home/vmr/second_future_id_abc_4_trust/p2abcengine-master/Code/core-abce/abce-services/future_id/genPresentationToken.sh";
   String testGenerationScriptPath = "/home/vmr/second_future_id_abc_4_trust/p2abcengine-master/Code/core-abce/abce-services/future_id/";

   String testVerificationScript = "/home/vmr/second_future_id_abc_4_trust/p2abcengine-master/Code/core-abce/abce-services/future_id/verify.sh";
   String testVerificationScriptPath = "/home/vmr/second_future_id_abc_4_trust/p2abcengine-master/Code/core-abce/abce-services/future_id/";
   String testPresentationPolicyDest = "/home/vmr/second_future_id_abc_4_trust/p2abcengine-master/Code/core-abce/abce-services/tutorial-resources/future_id_to_abc4_trust/my-app/src/main/java/com/mycompany/app/presentationPolicyAlternatives.xml";

   TokenGenerator abcUser = new TokenGenerator(testPolicy, testGenerationScript, testGenerationScriptPath);

   abcUser.generatePolicyToken(testPresentationPolicyDest);
   abcUser.selfTest(testVerificationScript, testVerificationScriptPath);
   System.out.println(abcUser.getPresentationToken("/home/vmr/second_future_id_abc_4_trust/p2abcengine-master/Code/core-abce/abce-services/future_id/presentationPolicyAlternativesAndPresentationToken.xml"));
  }

}
