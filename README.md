Anonymous Authentication Door
===================================

This is the door portion of an anonymous authentication proof-of-concept. This project implements the card half of the authentication protocol and sends responses back to the door through NFC.

The main protocol and security code can be found in `Application/src/main/java/com/example/android/cardreader/AccessCardReader.java` and `CardReaderFragment.java`. 

The project uses on the libanonauth security library, whose code can be found [here] (https://github.com/anon-auth/libanonauth).

This project is based heavily on Google's NFC Card Emulation/Card Reader samples.

Getting Started
---------------

This sample uses the Gradle build system. To build this project, use the
"gradlew build" command or use "Import Project" in Android Studio.

This Android code and its pair, anon-auth-card, are hard-coded with information enabling the card to access the door.
