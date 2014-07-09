# IRMA Configuration files

This repository contains all the configuration files for the irma project. It describes all the issuer and verifies and declares which credentials are issued respectively verified by these parties.

In the normal branch private keys of the issuers are not included. Therefore it is **highly recommended** to use the *demo* branch when developping. This branch has a seperate set of keys and does include a private key for every issuer.

## Directory structure
Stores configuration files per issuer/relying party. Typical directory structure:

	Organization
	+-- Issues
	|   +-- CredetialName
	|   	+--- description.xml
	|   	+--- id.txt
	|   	+--- structure.xml
	+-- Verifies
	|   +-- VerifySpecName
	|   	+--- description.xml
	|   	+--- specification.xml
	+-- private
	|   +-- isk.xml (not present in master branch)
	+-- description.xml
	+-- baseURL.txt
	+-- gp.xml
	+-- ipk.xml
	+-- logo.png
	+-- sp.xml

Finally, there is the special directory _android_ that contains a list of issuers and verifiers.

## Some notes on adding a new organization

 1. Make sure you add a description for your organization, and a logo.png file.
 2. Generate key material and put the public files into the tree (more information on this later)
 3. For every credential this organization issues, make sure you use a unique id.
 4. Remember to add your verifier/issuer to the appropriate lists in the android directory.