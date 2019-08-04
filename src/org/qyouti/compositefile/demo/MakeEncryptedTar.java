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
import java.security.Security;
import java.util.Arrays;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.qyouti.compositefile.EncryptedCompositeFile;

/**
 *
 * @author maber01
 */
public class MakeEncryptedTar
{

  /**
   * @param args the command line arguments
   */
  public static void main(String[] args)
  {
    int i;
    byte[] buffer = new byte[1024 * 8];
    Arrays.fill(buffer, (byte) 0x55);

    Security.addProvider(new BouncyCastleProvider());

    try
    {
      File file = new File("demo/mydataenc.tar");
      if ( file.exists() )
        file.delete();
      
      File aliceseckeyfile = new File( "demo/alice_secring.gpg" );
      File alicepubkeyfile = new File( "demo/alice_pubring.gpg" );
      
      KeyUtil ku = new KeyUtil( aliceseckeyfile, alicepubkeyfile );
      PGPPrivateKey  prikey = ku.getPrivateKey("alice", "alice".toCharArray() );
      PGPPublicKey  pubkey = ku.getPublicKey( "alice" );
      PGPPublicKey  otherpubkey = ku.getPublicKey( "bob" );
      
      OutputStream out;

      EncryptedCompositeFile compfile = EncryptedCompositeFile.getCompositeFile(file,prikey,"alice");
      compfile.addPublicKey( pubkey, "alice" );
      compfile.addPublicKey( otherpubkey, "bob" );
      out = compfile.getOutputStream("bigdatafile.bin.gpg", false);
      for (i = 0; i < 2; i++)
      {
        out.write(buffer);
      }
      out.close();

//            out = compfile.getOutputStream("little1.xml",false);
//            out.write(buffer);
//            out.close();
      compfile.close();

    } catch (Exception ex)
    {
      ex.printStackTrace();
    }
  }

}
