package org.qyouti.compositefile;


import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.channels.Channel;
import java.nio.channels.FileChannel;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author maber01
 */
public class AppendTar
{

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args)
    {
        byte[] buffer = new byte[512];
        Arrays.fill(buffer, (byte)0xaa );
        try
        {
            RandomAccessFile rafile = new RandomAccessFile( "mydata.tar", "rw" );
            System.out.println( "Position = " + Long.toHexString( rafile.getFilePointer() ) );
            long newpos = rafile.length() - 1024; //chan.position()-1024L;
            System.out.println( "Change to " + Long.toHexString(newpos) );
            rafile.seek(newpos);
            System.out.println( "Position = " + Long.toHexString( rafile.getFilePointer() ) );
            
            
            TarArchiveOutputStream tos = new TarArchiveOutputStream( new RandomOutputStreamDeprecated(rafile) );
            
            
            TarArchiveEntry entry = new TarArchiveEntry("little3.xml");
            entry.setSize(512);
            tos.putArchiveEntry(entry);
            tos.write(buffer);
            tos.closeArchiveEntry();
            
            
           
            tos.close();   // this is where the end of archive data is sent out

            rafile.close();
        }
        catch (Exception ex)
        {
            Logger.getLogger(AppendTar.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
