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

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;

/**
 *
 * @author maber01
 */
public class EncryptedCompositeFile
        extends CompositeFile
{

  static final HashMap<String, EncryptedCompositeFile> ecache = new HashMap<>();

  public static EncryptedCompositeFile getCompositeFile(File file, PGPPrivateKey key, String keyalias)
          throws IOException, NoSuchProviderException
  {
    String canonical = file.getCanonicalPath();
    EncryptedCompositeFile cf;
    synchronized (ecache)
    {
      cf = ecache.get(canonical);
      if (cf == null)
      {
        cf = new EncryptedCompositeFile(canonical, file, key, keyalias);
        ecache.put(canonical, cf);
      }
    }
    return cf;
  }

  static final private int PASS_STATUS_BLANK = 0;
  static final private int PASS_STATUS_UNKNOWN = 1;
  static final private int PASS_STATUS_KNOWN = 2;

  int passphrasestatus = PASS_STATUS_BLANK;
  char[] passphrase = null;
  String keyalias;
  PGPPrivateKey pgpkey;
  String jcaprovidername;
  PrivateKey jcakey;
  long jcakeyid;
  
  //OutputStream encryptedoutput = null;

  public EncryptedCompositeFile(String canonical, File file, String providername, PrivateKey key, long id, String keyalias)
          throws IOException, NoSuchProviderException
  {
    super(canonical, file);
    this.jcaprovidername = providername;
    this.keyalias = keyalias;
    this.jcakey = key;
    this.jcakeyid = id;
    initPrivateKey();
  }
  
  public EncryptedCompositeFile(String canonical, File file, PGPPrivateKey key, String keyalias)
          throws IOException, NoSuchProviderException
  {
    super(canonical, file);
    this.keyalias = keyalias;
    this.pgpkey = key;    
    initPrivateKey();
  }
  

  private void initPrivateKey() throws IOException, NoSuchProviderException
  {
    String name;
    for (ComponentEntry entry : componentmap.values())
    {
      name = entry.tararchiveentry.getName();
      if (name.startsWith("password_") && name.endsWith(".gpg"))
      {
        if (passphrasestatus == PASS_STATUS_BLANK)
        {
          passphrasestatus = PASS_STATUS_UNKNOWN;
        }
        if (name.equals("password_" + keyalias + ".gpg"))
        {
          InputStream in = super.getInputStream(name);
          passphrase = decryptPassphrase(in);
          in.close();
          System.out.println("Password is " + new String(passphrase));
          passphrasestatus = PASS_STATUS_KNOWN;
        }
      }
    }    
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
    } catch (PGPException ex)
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
    EncryptedInputWrapper inputwrapper = new EncryptedInputWrapper();
    try
    {
      inputwrapper.tarin = super.getInputStream(name);
      InputStream in = PGPUtil.getDecoderStream(inputwrapper.tarin);
      JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
      PGPEncryptedDataList enc;
      Object o = pgpF.nextObject();
      if (o instanceof PGPEncryptedDataList)
        enc = (PGPEncryptedDataList) o;
      else
        enc = (PGPEncryptedDataList) pgpF.nextObject();
      inputwrapper.pbe = (PGPPBEEncryptedData) enc.get(0);
      inputwrapper.clearin = inputwrapper.pbe.getDataStream(
              new JcePBEDataDecryptorFactoryBuilder(
                      new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()
              ).setProvider("BC").build(passphrase) );
      JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(inputwrapper.clearin);
      o = pgpFact.nextObject();
      if (o instanceof PGPCompressedData)
      {
        PGPCompressedData cData = (PGPCompressedData) o;        
        pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
        o = pgpFact.nextObject();
      } 
      PGPLiteralData ld = (PGPLiteralData) o;
      inputwrapper.literalin = ld.getInputStream();
      
      return inputwrapper;
      
    } catch (PGPException ex)
    {
      Logger.getLogger(EncryptedCompositeFile.class.getName()).log(Level.SEVERE, null, ex);
    }

    return null;
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

  private static byte[] encryptPassphrase(
          char[] passphrase,
          PGPPublicKey encKey,
          boolean withIntegrityCheck)
          throws IOException, NoSuchProviderException
  {
    try
    {
      byte[] pw = new String(passphrase).getBytes();
      ByteArrayOutputStream literal = new ByteArrayOutputStream();
      ByteArrayOutputStream encrypted = new ByteArrayOutputStream();

      PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
      lData.open(literal, PGPLiteralData.BINARY, "passphrase.txt", pw.length, new Date(System.currentTimeMillis())).write(pw);

      PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
              new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));
      encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
      OutputStream cOut = encGen.open(encrypted, literal.size());
      cOut.write(literal.toByteArray());
      cOut.flush();
      cOut.close();
      System.out.println("Encrypted password length = " + encrypted.size());
      return encrypted.toByteArray();
    } catch (PGPException e)
    {
      System.err.println(e);
      if (e.getUnderlyingException() != null)
      {
        e.getUnderlyingException().printStackTrace();
      }
    }
    return null;
  }

  private char[] decryptPassphrase( InputStream in )
          throws IOException, NoSuchProviderException
  {
    long keyid;
    if (  this.pgpkey != null )
      keyid = this.pgpkey.getKeyID();
    else
      keyid = this.jcakeyid;
    String pw = null;
    in = PGPUtil.getDecoderStream(in);

    try
    {
      JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
      PGPEncryptedDataList enc;
      Object o = pgpF.nextObject();
      //
      // the first object might be a PGP marker packet.
      //
      if (o instanceof PGPEncryptedDataList)
      {
        enc = (PGPEncryptedDataList) o;
      } else
      {
        enc = (PGPEncryptedDataList) pgpF.nextObject();
      }

      //
      // find the secret pgpkey
      //
      Iterator it = enc.getEncryptedDataObjects();
      PGPPublicKeyEncryptedData pbe = null;
      boolean found=false;
      while ( !found && it.hasNext())
      {
        pbe = (PGPPublicKeyEncryptedData) it.next();
        System.out.println( pbe.getKeyID() + " == " + keyid );
        if ( pbe.getKeyID() == keyid )
          found = true;
      }

      if ( !found )
      {
        throw new IllegalArgumentException("secret key for message not found.");
      }

      InputStream clear;
      if ( this.pgpkey != null )
        clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(pgpkey));
      else
        clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(jcaprovidername).build(jcakey));
      
      JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
      Object message = plainFact.nextObject();

      if (message instanceof PGPCompressedData)
      {
        PGPCompressedData cData = (PGPCompressedData) message;
        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
        message = pgpFact.nextObject();
      }

      if (message instanceof PGPLiteralData)
      {
        PGPLiteralData ld = (PGPLiteralData) message;
        InputStream unc = ld.getInputStream();
        ByteArrayOutputStream fOut = new ByteArrayOutputStream();
        Streams.pipeAll(unc, fOut);
        fOut.close();
        pw = fOut.toString();
        System.out.println("Pass " + pw);
      } else if (message instanceof PGPOnePassSignatureList)
      {
        throw new PGPException("encrypted message contains a signed message - not literal data.");
      } else
      {
        throw new PGPException("message is not a simple encrypted file - type unknown.");
      }

      if (pbe.isIntegrityProtected())
      {
        if (!pbe.verify())
        {
          System.err.println("message failed integrity check");
        } else
        {
          System.err.println("message integrity check passed");
        }
      } else
      {
        System.err.println("no message integrity check");
      }
    } catch (PGPException e)
    {
      System.err.println(e);
      if (e.getUnderlyingException() != null)
      {
        e.getUnderlyingException().printStackTrace();
      }
    }

    return pw.toCharArray();
  }

  public static final String passchars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ0123456789.,;:[]}{=+-_)(*&%$";

  public void addPublicKey(PGPPublicKey key, String name) throws IOException, NoSuchProviderException, NoSuchAlgorithmException
  {
    if (this.passphrasestatus == PASS_STATUS_UNKNOWN)
    {
      throw new IOException("Cannot determine password to cannot add access to another user.");
    }

    if (this.passphrasestatus == PASS_STATUS_BLANK)
    {
      SecureRandom sr = SecureRandom.getInstanceStrong();
      passphrase = new char[20];
      for (int i = 0; i < passphrase.length; i++)
      {
        passphrase[i] = passchars.charAt(sr.nextInt(passchars.length()));
      }
      System.out.println("Generated password: " + new String(passphrase));
      this.passphrasestatus = PASS_STATUS_KNOWN;
    }

    OutputStream out = super.getOutputStream("password_" + name + ".gpg", true);
    byte[] encrypted = encryptPassphrase(passphrase, key, true);
    out.write(encrypted);
    out.close();
  }

  
  
  class EncryptedInputWrapper
          extends InputStream
  {
    InputStream literalin;
    InputStream clearin;
    InputStream tarin;
    PGPPBEEncryptedData pbe;    
    
    @Override
    public boolean markSupported()
    {
      return literalin.markSupported(); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public synchronized void reset() throws IOException
    {
      literalin.reset(); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public synchronized void mark(int readlimit)
    {
      literalin.mark(readlimit); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void close() throws IOException
    {
      if (pbe.isIntegrityProtected())
      {
        try
        {
          if (!pbe.verify())
          {
            System.err.println("message failed integrity check");
          } else
          {
            System.err.println("message integrity check passed");
          }
        } catch (PGPException ex)
        {
            System.err.println("unable to run integrity check");
        }
      } else
      {
        System.err.println("no message integrity check");
      }
      closeInputStream();
      literalin.close();
    }

    @Override
    public int available() throws IOException
    {
      return literalin.available(); 
    }

    @Override
    public long skip(long n) throws IOException
    {
      return literalin.skip(n);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException
    {
      return literalin.read(b, off, len); 
    }

    @Override
    public int read(byte[] b) throws IOException
    {
      return read(b,0,b.length); 
    }

    @Override
    public int read() throws IOException
    {
      return literalin.read();
    }
    
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
      this.literaloutput = literaloutput;
    }

    @Override
    public void close()
            throws IOException
    {
      flush();
      literaloutput.close();   // complete the literal data packet
      compressiongen.close();  // complete the enclosing compression packet
      encryptedoutput.close(); // complete the enclosing encryption packet

      taroutput.close();       // now close the taroutput which encloses the whole lot.
    }

    @Override
    public void flush()
            throws IOException
    {
      literaloutput.flush();
    }

    @Override
    public void write(byte[] b, int off, int len)
            throws IOException
    {
      literaloutput.write(b, off, len);
    }

    @Override
    public void write(byte[] b)
            throws IOException
    {
      literaloutput.write(b, 0, b.length);
    }

    @Override
    public void write(int b)
            throws IOException
    {
      literaloutput.write(b);
    }

  }

}
