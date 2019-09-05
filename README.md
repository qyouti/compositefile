# compositefile
Java library, built on Apache Commons Compress that provides a kind of tar archive which is partially random access.
# Requirement
1. A file archive which is based on RandomAccessFile, instead of InputStream and/or OutputStream.
2. Ability to seek past uninteresting records to find and read one specific entry and extract it.
3. Ability to seek to end and append a new record.
4. Ability to archive an entry from a stream of unknown length, requiring that the header is written with indeterminate size information and after the actual data has been counted the library seeks back to header and updates it with the correct sizes.
5. Archive compatible with other 'tar' tools.
# Cryptography Requirements
1. OpenPGP compatible encryption of entries.
2. All component files readable by members of small team.
3. Any team member can add access for a new team member without reencoding the whole archive.
4. One random generated long password stored encrypted by each team member's public key.
5. Data component files encrypted with symmetric key made from fixed password and random salt.
6. Same password used for every data component but different salt.
# Status
Experimentation and basic working demo.
# Full Demo
At present, a demo of the tool can be made by running 'main' Java classes in sequence.  Files will be created in a subdirectory "demo" of the current directory.
1. Run AliceBobCharlieGenKeys to create OpenPGP keyrings for users alice, bob and charlie and create key pairs for them. All three users receive copies of the public keys. Charlie only gets a key pair if running on Windows - he gets a Windows CAPI key pair too which is only used to store/decrypt the password for his OpenPGP key store in a binary file.
2. Run AliceMakeEncryptedTar to create a composite file. Alice will encrypt it, put content in it and make it readable by herself and the other two.
3. Run BobReadEncryptedTar to check if Bob can extract data from the composite file.
4. Run CharlieReadEncryptedTar to check if Charlie can decrypt his keystore password and extract data from the composite file.
Step 4 will only work if the whole demo is run on a Windows computer.
