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

This client also contains an add-on (abc) for supporting the capabilities of the
IRMA card, together with a card info file for performing its detection. It requires all the libraries described at http://credentials.github.io/. In this respect, follow again the
instructions from http://credentials.github.io/ for generating the jar files. Then copy them to addons/abc/lib. The libraries 
can be instaled from addons/abcr as:

```
mvn install:install-file -Dfile=lib/credentials_api.dev.jar -DgroupId=org.irmacard.credentials -DartifactId=credentials -Dversion=1.0 -Dpackaging=org.irmacard.credentials
mvn install:install-file -Dfile=lib/credentials_idemix.dev.jar -DgroupId=org.irmacard.credentials.idemix -DartifactId=credentials-idemix -Dversion=1.0 -Dpackaging=org.irmacard.credentials.idemix
mvn install:install-file -Dfile=lib/idemix_library.dev.jar -DgroupId=com.ibm.zurich -DartifactId=ibm-idemix -Dversion=1.0 -Dpackaging=com.ibm.zurich
mvn install:install-file -Dfile=lib/idemix_terminal.dev.jar -DgroupId=org.irmacard.idemix -DartifactId=idemix-terminal -Dversion=1.0 -Dpackaging=org.irmacard.idemix
mvn install:install-file -Dfile=lib/scuba.dev.jar -DgroupId=net.sourceforge.scuba -DartifactId=scuba -Dversion=1.0 -Dpackaging=net.sourceforge.scuba
```

ABC4Trust integration
=====================

The abc4trust addon (addons/abc4trust) is used to generate presentation tokens from presentation policies
sent by a certain SP. It requires the full abc4trust implementation in addons/abc4trust/deployment.

Besides, the ABC4Trust engine must be
running in the client-side. Moreover, an issuer is expected to issue or have issued 
the credential that is being used during the verification. Building instructions can be found at 
https://forge.fi-ware.org/plugins/mediawiki/wiki/fiware/index.php/Privacy_-_Installation_and_Administration_Guide

Finally, the user webservice should be running in the client-side:

```
java -jar selfcontained-user-service.war 9200
```

This webservice can be loaded via the configuration menu of the client.

Build Instructions
==================

    $ mvn clean install

