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
 *
 * @author maber01
 */
public class CompositeFile
{
    static final HashMap<String,CompositeFile> cache = new HashMap<>();
    static byte[] zeroblock = new byte[512];
    
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
            System.out.println( "File entry: " + entry.getName() + "  length = " + entry.getSize() );
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
    
    public synchronized InputStream getInputStream( String name ) throws IOException
    {
        System.out.println( "Looking for entry: " + name );
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
    
    synchronized void closeInputStream()
    {
        currentinputstream = null;        
    }
    
    
    public synchronized OutputStream getOutputStream( String name, boolean replace ) throws IOException
    {
        System.out.println( "Looking for entry: " + name );
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
    
    
    synchronized void closeOutputStream() throws IOException
    {   
        long pos, size;
        currentoutputstream = null;
        tos.flush();
        pos = raf.getFilePointer();
        tos.closeArchiveEntry();              // pads to end of 512 byte block
        size = tos.getEntrySize();
        System.out.println( "            Wrote 0x" + Long.toHexString(size) + " = " + size + " bytes" );

        nextnewentry = raf.getFilePointer();  // pos for next component
        System.out.println( "Next new entry at 0x" + Long.toHexString(nextnewentry) );
        tos.close();                          // adds two blocks of zeros
        System.out.println( "           Now at 0x" + Long.toHexString(raf.getFilePointer()) );
        
        // now update the header with correct size
        newentry.tararchiveentry.setSize(size);
        raf.seek( newentry.pos );
        RandomOutputStream ros = new RandomOutputStream( raf );
        tos = new SeekableTarArchiveOutputStream( ros );
        tos.putArchiveEntry( newentry.tararchiveentry );
    }
    
    
    class TarOutputWrapper extends OutputStream
    {
      SeekableTarArchiveOutputStream tos;

      public TarOutputWrapper(SeekableTarArchiveOutputStream tos)
      {
        this.tos = tos;
      }

      @Override
      public void close()
              throws IOException
      {
        closeOutputStream();
      }

      @Override
      public void flush()
              throws IOException
      {
        tos.flush(); //To change body of generated methods, choose Tools | Templates.
      }

      @Override
      public void write(byte[] b, int off, int len)
              throws IOException
      {
        tos.write(b, off, len); //To change body of generated methods, choose Tools | Templates.
      }

      @Override
      public void write(byte[] b)
              throws IOException
      {
        tos.write(b); //To change body of generated methods, choose Tools | Templates.
      }

      @Override
      public void write(int b)
              throws IOException
      {
        tos.write(b);
      }
    }
    
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


    class RandomInputStream extends InputStream
    {
        RandomAccessFile raf;
        long mark = 0L;
        boolean dead=false;
        
        public RandomInputStream(RandomAccessFile raf)
        {
            this.raf = raf;
        }

        @Override
        public boolean markSupported()
        {
            return false;
        }

        @Override
        public synchronized void reset() throws IOException
        {
            throw new IOException( "Reset not supported." );
        }

        @Override
        public synchronized void mark(int readlimit)
        {
            // silently ignore
        }

        @Override
        public void close() throws IOException
        {
            closeInputStream();
        }

        @Override
        public int available() throws IOException
        {
            if ( dead )
                throw new IOException( "Attempt to use input stream after it was closed." );
            return 0;
        }

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

        @Override
        public int read() throws IOException
        {
            if ( dead )
                throw new IOException( "Attempt to use input stream after it was closed." );
            return raf.read();
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException
        {
            if ( dead )
                throw new IOException( "Attempt to use input stream after it was closed." );
            return raf.read(b, off, len); //To change body of generated methods, choose Tools | Templates.
        }

        @Override
        public int read(byte[] b) throws IOException
        {
            if ( dead )
                throw new IOException( "Attempt to use input stream after it was closed." );
            return raf.read(b); //To change body of generated methods, choose Tools | Templates.
        }
    }
    
    class ComponentEntry
    {
        long pos;
        long datapos = -1L;
        TarArchiveEntry tararchiveentry;

        public ComponentEntry(long pos, TarArchiveEntry tararchiveentry)
        {
            this.pos = pos;
            this.tararchiveentry = tararchiveentry;
        }
        
    }
}
