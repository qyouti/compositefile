package org.qyouti.compositefile;


import java.io.File;
import java.io.OutputStream;
import java.util.Arrays;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author maber01
 */
public class MakeTar
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
            OutputStream out;
            File file = new File( "mydata2.tar" );
            
            CompositeFile compfile = CompositeFile.getCompositeFile(file);
            out = compfile.getOutputStream("bigdatafile.bin",false);
            out.write(buffer);
            out.close();
            
            out = compfile.getOutputStream("little1.xml",false);
            out.write(buffer);
            out.close();
            
            compfile.close();
            
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
    }
    
}
