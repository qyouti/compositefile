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
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.qyouti.compositefile.EncryptedCompositeFile;

/**
 *
 * @author maber01
 */
public class Encrypt
{

  /**
   * @param args the command line arguments
   */
  public static void main(String[] args)
  {
    int i;
    byte[] data = new byte[1024*8];
    Arrays.fill(data, (byte)0x55 );    

    Security.addProvider(new BouncyCastleProvider());
    
    try
    {
      File file = new File("demo/test.txt.gpg");
      OutputStream fileoutput = new FileOutputStream(file);

      PGPEncryptedDataGenerator encryptiongen = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
              .setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC"));
      encryptiongen.addMethod(new JcePBEKeyEncryptionMethodGenerator("silly".toCharArray()).setProvider("BC"));
      OutputStream encryptedoutput = encryptiongen.open(fileoutput, new byte[1 << 16]);
      PGPLiteralDataGenerator literalgen = new PGPLiteralDataGenerator();
      PGPCompressedDataGenerator compressiongen = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
      OutputStream literalout = literalgen.open(compressiongen.open(encryptedoutput), PGPLiteralData.BINARY, "test.txt", new Date(System.currentTimeMillis()), new byte[1 << 16] );
      
      literalout.write("The spicy green turnip ran through the silly field.".getBytes());
      
      literalout.close();
      compressiongen.close();
      encryptedoutput.close();
    }
    catch (IOException ex)
    {
      Logger.getLogger(Encrypt.class.getName()).log(Level.SEVERE, null, ex);
    }
    catch (PGPException ex)
    {
      Logger.getLogger(Encrypt.class.getName()).log(Level.SEVERE, null, ex);
    }

  }

}
