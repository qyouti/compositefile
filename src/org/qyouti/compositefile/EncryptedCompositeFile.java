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
package org.qyouti.compositefile;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;

/**
 *
 * @author maber01
 */
public class EncryptedCompositeFile
        extends CompositeFile
{

  static final HashMap<String, EncryptedCompositeFile> ecache = new HashMap<>();

  public static EncryptedCompositeFile getCompositeFile(File file)
          throws IOException
  {
    String canonical = file.getCanonicalPath();
    EncryptedCompositeFile cf;
    synchronized (ecache)
    {
      cf = ecache.get(canonical);
      if (cf == null)
      {
        cf = new EncryptedCompositeFile(canonical, file);
        ecache.put(canonical, cf);
      }
    }
    return cf;
  }

  char[] passphrase = "sillypassword".toCharArray();
  //OutputStream encryptedoutput = null;

  public EncryptedCompositeFile(String canonical, File file)
          throws IOException
  {
    super(canonical, file);
  }

  @Override
  public synchronized OutputStream getOutputStream(String name, boolean replace)
          throws IOException
  {
    OutputStream taroutput = super.getOutputStream(name, replace);

    PGPEncryptedDataGenerator encryptiongen = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
            .setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC"));
    encryptiongen.addMethod(new JcePBEKeyEncryptionMethodGenerator(passphrase).setProvider("BC"));
    OutputStream encryptedoutput;
    try
    {
      encryptedoutput = encryptiongen.open(taroutput, new byte[1 << 16]);
    }
    catch (PGPException ex)
    {
      throw new IOException("Unable to initialise encrypted output.", ex);
    }
    PGPLiteralDataGenerator literalgen = new PGPLiteralDataGenerator();
    PGPCompressedDataGenerator compressiongen = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
    OutputStream literalout = literalgen.open(compressiongen.open(encryptedoutput), PGPLiteralData.BINARY, name, new Date(System.currentTimeMillis()), new byte[1 << 16]);

    return new EncryptedOutputWrapper(taroutput, encryptedoutput, compressiongen, literalout);
  }

  @Override
  synchronized void closeOutputStream()
          throws IOException
  {
    super.closeOutputStream();
  }

  @Override
  public synchronized InputStream getInputStream(String name)
          throws IOException
  {
    return super.getInputStream(name);
  }

  @Override
  synchronized void closeInputStream()
  {
    super.closeInputStream();
  }

  @Override
  public void close()
          throws IOException
  {
    super.close();
  }

  class EncryptedOutputWrapper
          extends OutputStream
  {

    OutputStream taroutput;
    OutputStream encryptedoutput;
    PGPCompressedDataGenerator compressiongen;
    OutputStream literaloutput;

    public EncryptedOutputWrapper(OutputStream taroutput, OutputStream encryptedoutput,
            PGPCompressedDataGenerator compressiongen, OutputStream literaloutput)
    {
      this.taroutput = taroutput;
      this.encryptedoutput = encryptedoutput;
      this.compressiongen = compressiongen;
      this.literaloutput = encryptedoutput;
    }

    @Override
    public void close()
            throws IOException
    {
      literaloutput.close();   // complete the literal data packet
      compressiongen.close();  // complete the enclosing compression packet
      encryptedoutput.close(); // complete the enclosing encryption packet

      taroutput.close();       // now close the taroutput which encloses the whole lot.
    }

    @Override
    public void flush()
            throws IOException
    {
      encryptedoutput.flush();
    }

    @Override
    public void write(byte[] b, int off, int len)
            throws IOException
    {
      encryptedoutput.write(b, off, len);
    }

    @Override
    public void write(byte[] b)
            throws IOException
    {
      encryptedoutput.write(b, 0, b.length);
    }

    @Override
    public void write(int b)
            throws IOException
    {
      encryptedoutput.write(b);
    }

  }

}
