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
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.qyouti.compositefile.EncryptedCompositeFile;
import org.qyouti.compositefile.EncryptedCompositeFileUser;

/**
 * Bob will read an entry in the demo encrypted composite file that was created by Alice.
 * @author maber01
 */
public class BobReadEncryptedTar
{

  /**
   * @param args the command line arguments
   */
  public static void main(String[] args)
  {
    Security.addProvider(new BouncyCastleProvider());
    
    try
    {
      int x, i;
      InputStream in;
      File file = new File("demo/mydataenc.tar");

      
      File bobseckeyfile = new File( "demo/bob_secring.gpg" );
      File bobpubkeyfile = new File( "demo/bob_pubring.gpg" );
      
      KeyUtil ku = new KeyUtil( bobseckeyfile, bobpubkeyfile );
      PGPPrivateKey  prikey = ku.getPrivateKey("bob", "bob".toCharArray() );      
      PGPPublicKey  pubkey = ku.getPublicKey("bob");
      
      EncryptedCompositeFileUser bob = new EncryptedCompositeFileUser("bob",prikey,pubkey, ku.pubringcoll );
      EncryptedCompositeFile compfile = EncryptedCompositeFile.getCompositeFile(file);
      
      in=compfile.getDecryptingInputStream(bob,"little.txt.gpg");
      System.out.print( "0  :  " );
      for ( i=0; (x = in.read()) >= 0; i++ )
      {
        if ( x>15 )
          System.out.print( Character.toString((char)x) /*Integer.toHexString(x)*/ );
        else
          System.out.print( "[0x" +Integer.toHexString(x) + "]" );
        if ( i%64 == 63 )
          System.out.print( "\n" +  Integer.toHexString(i+1) + "  :  " );
      }
      in.close();
      compfile.close();
      System.out.print( "\n\n" );
    }
    catch (IOException ex)
    {
      Logger.getLogger(BobReadEncryptedTar.class.getName()).log(Level.SEVERE, null, ex);
    } catch (PGPException ex)
    {
      Logger.getLogger(BobReadEncryptedTar.class.getName()).log(Level.SEVERE, null, ex);
    }

  }

}
