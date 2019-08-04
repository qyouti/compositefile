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
Experimentation and basic working demo. Class MakeEncryptedTar generates keys for Alice and Bob and puts some data in a new archive. ReadEncryptedTar attempts read a data file from the archive.
