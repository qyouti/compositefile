package org.qyouti.compositefile;


import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author maber01
 */
public class ReadTar
{

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args)
    {
        try
        {
            FileInputStream fis = new FileInputStream("mydata.tar");
            TarArchiveInputStream tis = new TarArchiveInputStream( fis );
            TarArchiveEntry entry=null;
            while ( (entry=tis.getNextTarEntry()) != null )
            {
                System.out.println( "File entry: " + entry.getName() + "  length = " + entry.getSize() );
            }
            tis.close();
            fis.close();
        }
        catch (IOException ex)
        {
            Logger.getLogger(ReadTar.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
    
}
