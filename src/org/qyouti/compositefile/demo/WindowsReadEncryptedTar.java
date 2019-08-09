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
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPPrivateKey;
 import org.qyouti.compositefile.CompositeFile;
import org.qyouti.compositefile.EncryptedCompositeFile;

/**
 *
 * @author maber01
 */
public class WindowsReadEncryptedTar
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

      File charliepubkeyfile = new File( "demo/charlie_pubring.gpg" );
      FileInputStream fin = new FileInputStream( charliepubkeyfile );
      KeyFingerPrintCalculator fpcalc = new BcKeyFingerprintCalculator();
      PGPPublicKeyRingCollection pubringcoll = new PGPPublicKeyRingCollection( fin, fpcalc );
      PGPPublicKeyRing keyring = pubringcoll.getKeyRings( "charlie" ).next();
      PGPPublicKey charliepubkey = keyring.getPublicKey();
      if ( charliepubkey != null )
        System.out.println( "Charlie public key id " + Long.toHexString(charliepubkey.getKeyID()) );
      
      KeyStore keyStore = KeyStore.getInstance("Windows-MY");
      keyStore.load(null, null);  // Load keystore 
      PrivateKey k = (PrivateKey)keyStore.getKey("Charlie", null );
      X509Certificate c = (X509Certificate)keyStore.getCertificate("Charlie");
      BigInteger serial = c.getSerialNumber();
      long s = serial.longValue();
      System.out.println( "Charlie's private key serial = " + Long.toHexString(s) );
      //JcaPGPPrivateKey wrappedkey = new JcaPGPPrivateKey( -7249575641428823772L, k );
      
      EncryptedCompositeFile compfile = EncryptedCompositeFile.getCompositeFile(file,keyStore.getProvider(),k,charliepubkey.getKeyID(),"charlie");
      
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
      Logger.getLogger(WindowsReadEncryptedTar.class.getName()).log(Level.SEVERE, null, ex);
    } catch (NoSuchProviderException ex)
    {
      Logger.getLogger(WindowsReadEncryptedTar.class.getName()).log(Level.SEVERE, null, ex);
    }
    catch (KeyStoreException ex)
    {
      Logger.getLogger(WindowsReadEncryptedTar.class.getName()).log(Level.SEVERE, null, ex);
    }
    catch (NoSuchAlgorithmException ex)
    {
      Logger.getLogger(WindowsReadEncryptedTar.class.getName()).log(Level.SEVERE, null, ex);
    }
    catch (CertificateException ex)
    {
      Logger.getLogger(WindowsReadEncryptedTar.class.getName()).log(Level.SEVERE, null, ex);
    }
    catch (UnrecoverableKeyException ex)
    {
      Logger.getLogger(WindowsReadEncryptedTar.class.getName()).log(Level.SEVERE, null, ex);
    }
    catch (PGPException ex)
    {
      Logger.getLogger(WindowsReadEncryptedTar.class.getName()).log(Level.SEVERE, null, ex);
    }

  }

}
