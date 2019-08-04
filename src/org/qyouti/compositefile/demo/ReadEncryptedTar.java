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
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.qyouti.compositefile.CompositeFile;
import org.qyouti.compositefile.EncryptedCompositeFile;

/**
 *
 * @author maber01
 */
public class ReadEncryptedTar
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

      
      File aliceseckeyfile = new File( "demo/alice_secring.gpg" );
      File alicepubkeyfile = new File( "demo/alice_pubring.gpg" );
      
      KeyUtil ku = new KeyUtil( aliceseckeyfile, alicepubkeyfile );
      PGPPrivateKey  prikey = ku.getPrivateKey("alice", "alice".toCharArray() );      
      EncryptedCompositeFile compfile = EncryptedCompositeFile.getCompositeFile(file,prikey,"alice");
      
      in=compfile.getInputStream("bigdatafile.bin.gpg");
      for ( i=0; (x = in.read()) >= 0; i++ )
      {
        System.out.println( Integer.toHexString(i) + "  :  " + Integer.toHexString(x) );
      }
      in.close();
      compfile.close();
    }
    catch (IOException ex)
    {
      Logger.getLogger(ReadEncryptedTar.class.getName()).log(Level.SEVERE, null, ex);
    } catch (PGPException ex)
    {
      Logger.getLogger(ReadEncryptedTar.class.getName()).log(Level.SEVERE, null, ex);
    } catch (NoSuchProviderException ex)
    {
      Logger.getLogger(ReadEncryptedTar.class.getName()).log(Level.SEVERE, null, ex);
    }

  }

}
