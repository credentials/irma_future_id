Prerequisites
=============

In order to build the Open eCard project, some additional tools are needed.

Required dependencies are:
* Java JDK 6 or higher
  Oracle JDK and OpenJDK are working correctly

* Maven 3.0.3 or higher
  https://maven.apache.org/download.html

* Git 1.7.11 or higher (older versions are probably also ok)
  http://git-scm.com/downloads

Optional dependencies are:
* Android SDK
  The Android SDK dependent modules are built when the environment variable
  ANDROID_HOME is set and points to the installation directory of the Android
  SDK.

  https://developer.android.com/sdk/index.html

* Android NDK
  The Android NDK dependent modules are built when the environment variable
  ANDROID_NDK_HOME is set and points to the installation directory of the
  Android NDK. The Android NDK has a direct dependency for the Android
  SDK. However due to restrictions in maven, no actual check is performed
  enforcing that the Android SDK must also be configured.

  https://developer.android.com/tools/sdk/ndk/index.html

* WiX
  The WiX executables must be available in the PATH environment variable.

  http://wixtoolset.org/


Prior to starting the build, all Git submodules must be initialized with the
following command, which must be issued form the project root:

  $ git submodule update --init

Git submodule updates may also be necessary after pulling changes from the
remote repository. The `git status` command indicates when this is needed.


Build Sources
=============

A standard build is performed by the command:

  $ mvn clean install

In order to create Javadoc and source artifacts, perform the following command:

  $ mvn clean javadoc:javadoc javadoc:jar source:jar install


Build Profiles
--------------

The Open eCard project uses Maven profiles to modify how the build is
performed and which artifacts are created.

Maven profiles are selected on the commandline by adding the -P option as
follows:

  $ mvn -Pprofile1,profile2 <Maven goals>


The following global profiles are defined:
* `release`
  Remove debugging symbols from Java bytecode.

The following profiles are module specific:

Module `clients/applet`
* `trace-applet`
  Bundle SLF4J extension artifact, so that the applet can emit trace logs.

Module `clients/richclient`
* `windows-installer`
  Use the WiX tools to create an msi (MicroSoft Installer) package.


Code Signing
------------

The `applet` and `richclient` modules produce signed artifacts. A dummy
certificate is included in the source distribution, so the build runs in any
case. If another certificate from a trusted CA should be used, then the
following fragment must be inserted into `$HOME/.m2/settings.xml`:

  <profiles>
    <profile>
      <id>override-sign</id>
      <activation>
        <activeByDefault>true</activeByDefault>
      </activation>
      <properties>
        <sign.keystore>PATH_TO_JAVA_KEYSTORE</sign.keystore>
        <sign.storepass>KEYSTORE_PASSWORD</sign.storepass>
        <sign.keypass>CERTIFICATE_KEY_PASSWORD</sign.keypass>
        <sign.alias>CERTIFICATE_ALIAS</sign.alias>
      </properties>
    </profile>
  </profiles>
