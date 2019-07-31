package org.qyouti.compositefile;


import java.io.FileOutputStream;
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
public class OldMakeTar
{

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args)
    {
        byte[] buffer = new byte[512];
        Arrays.fill(buffer, (byte)0x55 );
        try
        {
            FileOutputStream fos = new FileOutputStream("mydata.tar", false);
            TarArchiveOutputStream tos = new TarArchiveOutputStream( fos );
            
            TarArchiveEntry entry = new TarArchiveEntry( "bigdatafile.bin" );
            entry.setSize(512);
            tos.putArchiveEntry(entry);
            tos.write(buffer);
            tos.closeArchiveEntry();
            
            entry = new TarArchiveEntry( "little1.xml");
            entry.setSize(512);
            tos.putArchiveEntry(entry);
            tos.write(buffer);
            tos.closeArchiveEntry();
            
            tos.close();
        }
        catch (Exception ex)
        {
            Logger.getLogger(AppendTar.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
}
