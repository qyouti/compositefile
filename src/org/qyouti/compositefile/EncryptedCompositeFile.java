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
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
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
    static final HashMap<String,EncryptedCompositeFile> ecache = new HashMap<>();
    
    public static EncryptedCompositeFile getCompositeFile( File file ) throws IOException
    {
        String canonical = file.getCanonicalPath();
        EncryptedCompositeFile cf;
        synchronized ( ecache )
        {
            cf = ecache.get(canonical);
            if ( cf == null )
            {
                cf = new EncryptedCompositeFile( canonical, file );
                ecache.put( canonical, cf );
            }
        }
        return cf;
    }
    
    
  String passphrase = "sillypassword";
  OutputStream encryptedoutput=null;
          
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
    byte[] buffer = new byte[0x400];
    
    PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
            .setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC"));
    encGen.addMethod(new JcePBEKeyEncryptionMethodGenerator(passphrase.toCharArray()).setProvider("BC"));
    try
    {
      encryptedoutput = encGen.open(taroutput, buffer);
    }
    catch (PGPException ex)
    {
      Logger.getLogger(EncryptedCompositeFile.class.getName()).log(Level.SEVERE, null, ex);
      throw new IOException( "Unable to initialise encryption of file", ex );
    }
    
    return new EncryptedOutputWrapper( taroutput, encryptedoutput );
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

  
  class EncryptedOutputWrapper extends OutputStream
  {
    OutputStream taroutput;
    OutputStream encryptedoutput;

    public EncryptedOutputWrapper(OutputStream taroutput, OutputStream encryptedoutput)
    {
      this.taroutput = taroutput;
      this.encryptedoutput = encryptedoutput;
    }    
      
    @Override
    public void close()
            throws IOException
    {
      encryptedoutput.close(); // this doesn't close taroutput it just flushes out openpgp data
      taroutput.close();       // now close the taroutput
    }

    @Override
    public void flush()
            throws IOException
    {
      encryptedoutput.flush(); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void write(byte[] b, int off, int len)
            throws IOException
    {
      encryptedoutput.write(b, off, len); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void write(byte[] b)
            throws IOException
    {
      encryptedoutput.write(b); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void write(int b)
            throws IOException
    {
      encryptedoutput.write(b);
    }
    
  }
  
  
  
  
}
