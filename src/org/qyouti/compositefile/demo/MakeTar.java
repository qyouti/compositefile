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

package org.qyouti.compositefile.demo;


import java.io.File;
import java.io.OutputStream;
import java.util.Arrays;
import org.qyouti.compositefile.CompositeFile;



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
        int i;
        byte[] buffer = new byte[1024*8];
        Arrays.fill(buffer, (byte)0x55 );
        try
        {
            OutputStream out;
            File file = new File( "mydata2.tar" );
            
            CompositeFile compfile = CompositeFile.getCompositeFile(file);
            out = compfile.getOutputStream("bigdatafile.bin",false);
            for ( i=0; i<10000; i++ )
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
