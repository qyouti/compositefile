# compositefile
Java library, built on Apache Commons Compress that provides a kind of tar archive which is partially random access.
# Requirement
1. A file archive which is based on RandomAccessFile, instead of InputStream and/or OutputStream.
2. Ability to seek past uninteresting records to find and read one specific entry and extract it.
3. Ability to seek to end and append a new record.
4. Ability to archive an entry from a stream of unknown length, requiring that the header is written with indeterminate size information and after the actual data has been counted the library seeks back to header and updates it with the correct sizes.
# Status
Experimentation and partial functionality
