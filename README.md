About Open eCard
================

In the context of the Open eCard Project, industrial as well as academic
experts have decided to work together on providing an open source and cross
platform implementation of the eCard-API-Framework (BSI-TR-03112), through
which arbitrary applications can utilize authentication and signatures with
arbitrary chip cards.

The artifacts of the project consist of modularized, and to some extent
extensible, libraries as well as client implementations such as a Desktop
application (richclient), an Android app and a Java Applet.

IRMA integration
================

This client also contains different add-ons for supporting the capabilities of the
IRMA card, together with a card info file for performing its detection.

<table>
  <tr>
    <th>Name</th><th>Description</th>
  </tr>
  <tr>
    <td>irma-pin</td><td>It supports the authentication/updating processes of the admin and credential pins.</td>
  </tr>
  <tr>
    <td>irma-log</td><td>The card log can be read trough this add-on.</td>
  </tr>
  <tr>
    <td>irma-status</td><td>This add-on provides information about the status of the card.</td>
  </tr>
  <tr>
    <td>irma-credential</td><td>This add-on provides a list of the credentials available in the card.</td>
  </tr>
  <tr>
    <td>irma-prover</td><td>The Idemix proofs are generated through this add-on. If an IRMA card is connected
it is used in order to generate a proof according to a desired configuration (See https://github.com/credentials/irma_configuration).
Otherwise, a software credential from ABC4Trust is utilized.</td> 
  </tr>
</table>

Build Instructions
==================

Detailed build instructions can be found in the INSTALL.md file bundled with
this source package.

### ABC4Trust

In order to use the irma-prover add-on without having an IRMA token connected, the ABC4Trust engine must be
running in the client-side. Moreover, an issuer is expected to issue or have issued 
the credential that is being used during the verification. Building instructions can be found at 
https://forge.fi-ware.org/plugins/mediawiki/wiki/fiware/index.php/Privacy_-_Installation_and_Administration_Guide

Finally, the user webservice should be running in the client-side:

```
java -jar selfcontained-user-service.war 9200
```

Quick Start
-----------

The simplified build instructions are as follows:
```
$ cd open-ecard
$ git submodule init
$ git submodule update
```

The irma-log add-on requires two external libraries, SCUBA and irma-terminal, that are available from
<a href=https://github.com/credentials/>here</a>. In order to generate jar files for them, follow the
instructions at http://credentials.github.io/. Then, create a lib/ directory at addons/irma-log and copy there
the two jar files. Then, install the libraries with maven from the irma-log directory:

```
mvn install:install-file -Dfile=lib/idemix_terminal.dev.jar -DgroupId=org.irmacard.idemix -DartifactId=idemix-terminal -Dversion=1.0 -Dpackaging=org.irmacard.idemix
mvn install:install-file -Dfile=lib/scuba.dev.jar -DgroupId=net.sourceforge.scuba -DartifactId=scuba -Dversion=1.0 -Dpackaging=net.sourceforge.scuba
```

Moreover, the irma-prover addon requires all the libraries described at http://credentials.github.io/. In this respect, follow again the
instructions from http://credentials.github.io/ for generating the jar files. Then copy them to addons/irma-prover/lib. The libraries 
can be instaled from addons/irma-prover as:

```
mvn install:install-file -Dfile=lib/credentials_api.dev.jar -DgroupId=org.irmacard.credentials -DartifactId=credentials -Dversion=1.0 -Dpackaging=org.irmacard.credentials
mvn install:install-file -Dfile=lib/credentials_idemix.dev.jar -DgroupId=org.irmacard.credentials.idemix -DartifactId=credentials-idemix -Dversion=1.0 -Dpackaging=org.irmacard.credentials.idemix
mvn install:install-file -Dfile=lib/idemix_library.dev.jar -DgroupId=com.ibm.zurich -DartifactId=ibm-idemix -Dversion=1.0 -Dpackaging=com.ibm.zurich
mvn install:install-file -Dfile=lib/idemix_terminal.dev.jar -DgroupId=org.irmacard.idemix -DartifactId=idemix-terminal -Dversion=1.0 -Dpackaging=org.irmacard.idemix
mvn install:install-file -Dfile=lib/scuba.dev.jar -DgroupId=net.sourceforge.scuba -DartifactId=scuba -Dversion=1.0 -Dpackaging=net.sourceforge.scuba
```

Finally:

```
    $ mvn clean install
```

License
=======

The Open eCard App uses a Dual Licensing model. The software is always
distributed under the GNU General Public License v3 (GPLv3). Additionally the
software can be licensed in an individual agreement between the licenser and
the licensee.


Contributing
============

New developers can find information on how to participate under
https://dev.openecard.org/projects/open-ecard/wiki/Developer_Guide.

Contributions can only be accepted when the contributor has signed the
contribution agreement (https://dev.openecard.org/documents/35). The agreement
basically states, that the contributed work can, additionally to the GPLv3, be
made available to others in an individual agreement as defined in the previous
section. For further details refer to the agreement.
