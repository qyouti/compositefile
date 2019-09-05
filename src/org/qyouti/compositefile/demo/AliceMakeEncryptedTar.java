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
import org.qyouti.compositefile.EncryptedCompositeFileUser;

/**
 * Alice creates an encrypted composite file. She will add herself and Bob to the users
 * who can read it.  If Charlie's key pair was generated he will be added too.  Data is
 * added to the archive.
 * 
 * @author maber01
 */
public class AliceMakeEncryptedTar
{

  /**
   * @param args the command line arguments
   */
  public static void main(String[] args)
  {
    int i;
    byte[] buffer = "The quick brown fox jumps over the lazy dog. \n".getBytes();

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
      PGPPublicKey  pubkeythree = ku.getPublicKey( "charlie" );
      
      OutputStream out;
      EncryptedCompositeFileUser alice = new EncryptedCompositeFileUser("alice", prikey, pubkey );
      
      EncryptedCompositeFile compfile = EncryptedCompositeFile.getCompositeFile(file);
      compfile.addPublicKey( alice, pubkey, "alice" );
      compfile.addPublicKey( alice, otherpubkey, "bob" );
      if ( pubkeythree != null )
        compfile.addPublicKey( alice, pubkeythree, "charlie" );
      out = compfile.getEncryptingOutputStream(alice,"bigdatafile.bin.gpg", false);
      for (i = 0; i < 202; i++)
      {
        out.write(buffer);
      }
      out.close();

      
      buffer = "Mary had a little lamb, its fleece was white as snow and everywhere that Mary went the lamb was sure to go. \n".getBytes();      
      out = compfile.getEncryptingOutputStream(alice,"little.txt.gpg",false);
      out.write(buffer);
      out.close();
      compfile.close();

    } catch (Exception ex)
    {
      ex.printStackTrace();
    }
  }

}
