/*
 * Copyright 2019 Leeds Beckett University.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.qyouti.compositefile;


import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;
import java.util.HashMap;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.archivers.tar.TarConstants;


/**
 * CompositeFile provides a way to append files to a 'tar' archive and
 * to write files whose length is unknown until the output stream is 
 * closed. Builds on Apache Commons.
 * @author maber01
 */
public class CompositeFile
{
    static final HashMap<String,CompositeFile> cache = new HashMap<>();
    static byte[] zeroblock = new byte[512];
    
    /**
     * Retrieves an active composite file from a cache or makes a
     * new one.  The intention is to make it safe for two different
     * threads to work with the same composite file - requests to
     * read/write files will block until other thread has completed
     * work.  Not tested as yet.
     * @param file
     * @return
     * @throws IOException 
     */
    public static CompositeFile getCompositeFile( File file ) throws IOException
    {
        String canonical = file.getCanonicalPath();
        CompositeFile cf;
        synchronized ( cache )
        {
            cf = cache.get(canonical);
            if ( cf == null )
            {
                cf = new CompositeFile( canonical, file );
                cache.put( canonical, cf );
            }
        }
        return cf;
    }
    
    private final String canonical;
    private final File file;
    private final RandomAccessFile raf;
    private final FileLock lock;
    private final boolean exists;
    private InputStream currentinputstream = null;
    private OutputStream currentoutputstream = null;
    private SeekableTarArchiveOutputStream tos;
    private ComponentEntry newentry;
        
    HashMap<String,ComponentEntry> componentmap = new HashMap<>();
    private long nextnewentry=0L;
    
    /**
     * Constructs a composite file based on the canonical path to
     * a tar file and a File referring to it. If the tar doesn't
     * exist it will be created and then its contents are indexed.
     * 
     * @param canonical The canonical path to the tar archive file.
     * @param file The tar file.
     * @throws IOException 
     */
    CompositeFile( String canonical, File file ) throws IOException
    {
        this.canonical = canonical;
        this.file = file;
        exists=file.exists();
        raf = new RandomAccessFile( file, "rwd" );
        // now the file will exist - if 'exists == true' it will be empty
        lock = raf.getChannel().lock();
        if ( !exists )
        {
            raf.write( zeroblock );
            raf.write( zeroblock );
            raf.seek(0);
        }
        
        readComponentMap();
    }
    
    /**
     * Closes the underlying RandomAccessFile and removes this
     * from the cache.
     * 
     * @throws IOException 
     */
    public void close() throws IOException
    {
        synchronized ( this )
        {
            lock.release();
            raf.close();
        }
        synchronized ( cache )
        {
            cache.remove( canonical );
        }
    }
    
    
    /**
     * Read headers for all entries in the tar file and make a map.
     * 
     * @throws IOException 
     */
    private void readComponentMap() throws IOException
    {
        componentmap.clear();
        raf.seek(0L);
        RandomInputStream ris = new RandomInputStream( raf );
        TarArchiveInputStream tis = new TarArchiveInputStream( ris );
        TarArchiveEntry entry;
        long pos = raf.getFilePointer();
        long size, extra, block;
        while ( (entry=tis.getNextTarEntry()) != null )
        {
            //System.out.println( "File entry: " + entry.getName() + "  length = " + entry.getSize() );
            // later entry will overwrite older entries - appropriately
            componentmap.put( entry.getName(), new ComponentEntry( pos, entry ) );
            
            // need to add entry size to find pointer to next entry
            size = entry.getSize();
            block = tis.getRecordSize();
            extra = 0;
            if ( size > 0 && (size % block) != 0 )
              extra = block - (size % block);
            pos = raf.getFilePointer() + size + extra;
        }
        nextnewentry = pos;
        tis.close();
    }
    
    /**
     * Initialise an InputStream which will read the contents of an entry.
     * 
     * @param name The (relative) path name of the entry.
     * @return An InputStream for reading content from.
     * @throws IOException 
     */
    public synchronized InputStream getInputStream( String name ) throws IOException
    {
        //System.out.println( "Looking for entry: " + name );
        if ( currentinputstream != null || currentoutputstream != null )
            throw new IOException( "Attempt to get data from composite file before previous operation has completed." );        
        ComponentEntry entry=componentmap.get( name );
        if ( entry==null )
            throw new IOException( "Component not found in CompositeFile " + name );
        raf.seek( entry.pos );
        RandomInputStream ris = new RandomInputStream( raf );
        TarArchiveInputStream tis = new TarArchiveInputStream( ris );
        tis.getNextTarEntry();
        currentinputstream = tis;
        return currentinputstream;
    }    
    
    /**
     * This will be called when the InputStream from getInputStream() is closed.
     */
    synchronized void closeInputStream()
    {
        currentinputstream = null;        
    }
    
    /**
     * Returns an OutputStream for writing data to an entry in the CompositeFile.
     * The entry will be completed when the OutputStream is closed.
     * 
     * @param name The relative path name within the tar archive.
     * @param replace Should the entry go ahead even if there is already an entry with the given name.
     * @return
     * @throws IOException 
     */
    public synchronized OutputStream getOutputStream( String name, boolean replace ) throws IOException
    {
        //System.out.println( "Looking for entry: " + name );
        if ( currentinputstream != null || currentoutputstream != null )
            throw new IOException( "Attempt to get data from composite file before previous operation has completed." );        
        ComponentEntry oldentry=componentmap.get( name );
        // content has indefinate length so allow lots of space
        // so TarArchiveOutputStream doesn't throw an exception when
        // content exceeds size. Will need to seek back and update the entry.
        if ( oldentry!=null && !replace )
            throw new IOException( "Component already in CompositeFile " + name );
        
        newentry = new ComponentEntry( nextnewentry, new TarArchiveEntry( name ) );    
        newentry.tararchiveentry.setSize(TarConstants.MAXSIZE);

        raf.seek( newentry.pos );
        RandomOutputStream ros = new RandomOutputStream( raf );
        tos = new SeekableTarArchiveOutputStream( ros );
        tos.putArchiveEntry(newentry.tararchiveentry);
        newentry.datapos = raf.getFilePointer();
        currentoutputstream = new TarOutputWrapper( tos );
        return currentoutputstream;
    }    
    
    /**
     * This is called when the client code closes the OutputStream it
     * received from calling getOutputStream(). It completes the tar
     * entry, seeks back to the header to correct the file size and then
     * appends end of file records to the tar.
     * 
     * @throws IOException 
     */
    synchronized void closeOutputStream() throws IOException
    {   
        long pos, size;
        currentoutputstream = null;
        tos.flush();
        pos = raf.getFilePointer();
        tos.closeArchiveEntry();              // pads to end of 512 byte block
        size = tos.getEntrySize();
        //System.out.println( "            Wrote 0x" + Long.toHexString(size) + " = " + size + " bytes" );

        nextnewentry = raf.getFilePointer();  // pos for next component
        //System.out.println( "Next new entry at 0x" + Long.toHexString(nextnewentry) );
        tos.close();                          // adds two blocks of zeros
        //System.out.println( "           Now at 0x" + Long.toHexString(raf.getFilePointer()) );
        
        // now update the header with correct size
        newentry.tararchiveentry.setSize(size);
        raf.seek( newentry.pos );
        RandomOutputStream ros = new RandomOutputStream( raf );
        tos = new SeekableTarArchiveOutputStream( ros );
        tos.putArchiveEntry( newentry.tararchiveentry );
    }
    
    /**
     * This utility class wraps the stream which writes data to the
     * tar archive so that the close() method can be intercepted and so
     * closeOutputStream() is called at the right point.
     */
    class TarOutputWrapper extends OutputStream
    {
      SeekableTarArchiveOutputStream tos;

      /**
       * Construct wrapper
       * @param tos The stream which will put data in the tar archive.
       */
      public TarOutputWrapper(SeekableTarArchiveOutputStream tos)
      {
        this.tos = tos;
      }

      /**
       * Instead of closing the wrapped stream this calls into CompositeFile.closeOutputStream()
       * to ensure an orderly end to the new entry.
       * 
       * @throws IOException 
       */
      @Override
      public void close()
              throws IOException
      {
        closeOutputStream();
      }

      /**
       * Just hands on to wrapped class.
       * @throws IOException 
       */
      @Override
      public void flush()
              throws IOException
      {
        tos.flush(); //To change body of generated methods, choose Tools | Templates.
      }

      /**
       * Just hands on to wrapped class.
       * 
       * @param b
       * @param off
       * @param len
       * @throws IOException 
       */
      @Override
      public void write(byte[] b, int off, int len)
              throws IOException
      {
        tos.write(b, off, len); //To change body of generated methods, choose Tools | Templates.
      }

      /**
       * Just hands on to wrapped class.
       * 
       * @param b
       * @throws IOException 
       */
      @Override
      public void write(byte[] b)
              throws IOException
      {
        tos.write(b); //To change body of generated methods, choose Tools | Templates.
      }

      /**
       * Just hands on to wrapped class.
       * 
       * @param b
       * @throws IOException 
       */
      @Override
      public void write(int b)
              throws IOException
      {
        tos.write(b);
      }
    }

    /**
     * Provides RandomOutputFile with InputStream interface.
     */
    class RandomOutputStream extends OutputStream
    {
        RandomAccessFile rafile;
        boolean dead=false;
        public RandomOutputStream(RandomAccessFile rafile)
        {
            this.rafile = rafile;
        }

        @Override
        public void write(int b) throws IOException
        {
            if ( dead )
                throw new IOException( "Attempt to use output stream after it was closed." );
            rafile.write(b);
        }

        @Override
        public void close() throws IOException
        {
            dead=true;
        }

        @Override
        public void flush() throws IOException
        {
            // nop
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException
        {
            if ( dead )
                throw new IOException( "Attempt to use output stream after it was closed." );
            rafile.write(b, off, len);
        }

        @Override
        public void write(byte[] b) throws IOException
        {
            if ( dead )
                throw new IOException( "Attempt to use output stream after it was closed." );
            rafile.write(b);
        }

    }


    /**
     * Provides RandomAccessFile with InputStream interface.
     */
    class RandomInputStream extends InputStream
    {
        RandomAccessFile raf;
        long mark = 0L;
        boolean dead=false;
        
        /**
         * 
         * @param raf 
         */
        public RandomInputStream(RandomAccessFile raf)
        {
            this.raf = raf;
        }

        /**
         * 
         * @return 
         */
        @Override
        public boolean markSupported()
        {
            return false;
        }

        /**
         * 
         * @throws IOException 
         */
        @Override
        public synchronized void reset() throws IOException
        {
            throw new IOException( "Reset not supported." );
        }

        /**
         * 
         * @param readlimit 
         */
        @Override
        public synchronized void mark(int readlimit)
        {
            // silently ignore
        }

        /**
         * 
         * @throws IOException 
         */
        @Override
        public void close() throws IOException
        {
            closeInputStream();
        }

        /**
         * 
         * @return
         * @throws IOException 
         */
        @Override
        public int available() throws IOException
        {
            if ( dead )
                throw new IOException( "Attempt to use input stream after it was closed." );
            return 0;
        }

        /**
         * 
         * @param n
         * @return
         * @throws IOException 
         */
        @Override
        public long skip(long n) throws IOException
        {
            if ( dead )
                throw new IOException( "Attempt to use input stream after it was closed." );
            long pos = raf.getFilePointer();
            pos = pos + n;
            raf.seek(pos);
            return n;
        }

        /**
         * 
         * @return
         * @throws IOException 
         */
        @Override
        public int read() throws IOException
        {
            if ( dead )
                throw new IOException( "Attempt to use input stream after it was closed." );
            return raf.read();
        }

        /**
         * 
         * @param b
         * @param off
         * @param len
         * @return
         * @throws IOException 
         */
        @Override
        public int read(byte[] b, int off, int len) throws IOException
        {
            if ( dead )
                throw new IOException( "Attempt to use input stream after it was closed." );
            return raf.read(b, off, len); //To change body of generated methods, choose Tools | Templates.
        }

        /**
         * 
         * @param b
         * @return
         * @throws IOException 
         */
        @Override
        public int read(byte[] b) throws IOException
        {
            if ( dead )
                throw new IOException( "Attempt to use input stream after it was closed." );
            return raf.read(b); //To change body of generated methods, choose Tools | Templates.
        }
    }
    
    /**
     * Simple data structure to hold additional data on TarArchiveEntry.
     * Built when indexing the tar file and as new entries are made.
     */
    class ComponentEntry
    {
      public long pos;
      long datapos = -1L;
      TarArchiveEntry tararchiveentry;

      /**
       * 
       * @param pos
       * @param tararchiveentry 
       */
      public ComponentEntry(long pos, TarArchiveEntry tararchiveentry)
      {
          this.pos = pos;
          this.tararchiveentry = tararchiveentry;
      }        
    }
}
