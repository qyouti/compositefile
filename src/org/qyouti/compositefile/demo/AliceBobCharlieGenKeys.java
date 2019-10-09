/*
 * Copyright 2019 jon.
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

import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Date;
import java.util.UUID;
import javax.crypto.Cipher;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.qyouti.compositefile.EncryptedCompositeFile;
import org.qyouti.winselfcert.WindowsCertificateGenerator;
import static org.qyouti.winselfcert.WindowsCertificateGenerator.CRYPT_USER_PROTECTED;
import static org.qyouti.winselfcert.WindowsCertificateGenerator.MS_ENH_RSA_AES_PROV;
import static org.qyouti.winselfcert.WindowsCertificateGenerator.PROV_RSA_AES;

/**
 * Generates RSA PGPPublicKey/PGPSecretKey pairs for demos.
 * Alice and Bob get PGP key pairs stored in their secret key rings. The
 * two public keys are put into Alice, Bob and Charlie's public key rings.
 * (Charlie will use Windows CAPI for his key pair.)
 */
public class AliceBobCharlieGenKeys
{

  PGPSecretKeyRingCollection[] secringcoll = new PGPSecretKeyRingCollection[3];
  PGPPublicKeyRingCollection[] pubringcoll = new PGPPublicKeyRingCollection[3];
  
  String[] aliases = { "alice", "bob", "charlie" };
  
  private void createKeyRings() throws IOException, PGPException
  {
    secringcoll[0] = new PGPSecretKeyRingCollection( new ArrayList<>() );
    secringcoll[1] = new PGPSecretKeyRingCollection( new ArrayList<>() );
    secringcoll[2] = new PGPSecretKeyRingCollection( new ArrayList<>() );
    
    pubringcoll[0] = new PGPPublicKeyRingCollection( new ArrayList<>() );
    pubringcoll[1] = new PGPPublicKeyRingCollection( new ArrayList<>() );    
    pubringcoll[2] = new PGPPublicKeyRingCollection( new ArrayList<>() );    
  }
  
  
  private void saveKeyRings() throws IOException
  {
    FileOutputStream out;
    
    for ( int i=0; i<aliases.length; i++ )
    {
      if ( secringcoll[i] != null )
      {
        out = new FileOutputStream("demo/" + aliases[i] + "_secring.gpg");
        secringcoll[i].encode(out);
        out.close();
      }

      out = new FileOutputStream("demo/" + aliases[i] + "_pubring.gpg");
      pubringcoll[i].encode(out);
      out.close();
    }
  }
  
  
  private void exportKeyPair(
          int secretOut,
          KeyPair pair,
          String identity,
          char[] passPhrase)
          throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException
  {

    PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
    PGPKeyPair keyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, pair, new Date());
    PGPSecretKey secretKey = new PGPSecretKey(
            PGPSignature.DEFAULT_CERTIFICATION,
            keyPair,
            identity,
            sha1Calc,
            null,
            null,
            new JcaPGPContentSignerBuilder(
                    keyPair.getPublicKey().getAlgorithm(),
                    HashAlgorithmTags.SHA1),
            new JcePBESecretKeyEncryptorBuilder(
                    PGPEncryptedData.CAST5,
                    sha1Calc).setProvider("BC").build(passPhrase));
    PGPPublicKey key = secretKey.getPublicKey();

    ArrayList<PGPSecretKey> seckeylist = new ArrayList<>();
    seckeylist.add(secretKey);
    PGPSecretKeyRing secretKeyRing = new PGPSecretKeyRing(seckeylist);

    ArrayList<PGPPublicKey> keylist = new ArrayList<>();
    keylist.add(key);
    PGPPublicKeyRing keyring = new PGPPublicKeyRing(keylist);
    
    // add secret stuff to own
    secringcoll[secretOut] = PGPSecretKeyRingCollection.addSecretKeyRing( secringcoll[secretOut], secretKeyRing );
    // add public to all
    for ( int i=0; i<pubringcoll.length; i++ )
      pubringcoll[i] = PGPPublicKeyRingCollection.addPublicKeyRing( pubringcoll[i], keyring );
  }


  private void run()
          throws Exception
  {
    Security.addProvider(new BouncyCastleProvider());

    char[] charliepassword = makeWindowsPasswordGuard();
    
    // Create key rings for all the demo users
    createKeyRings();
    
    // Create key pairs
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
    kpg.initialize(2048);
    KeyPair alicekp = kpg.generateKeyPair();
    kpg.initialize(2048);
    KeyPair bobkp = kpg.generateKeyPair();
    
    // Put keys pairs in OpenPGP format and put in OpenPGP key rings
    exportKeyPair( 0, alicekp, "alice", "alice".toCharArray() );
    exportKeyPair( 1, bobkp, "bob", "bob".toCharArray() );
    
    // Do charlie's keys if we are on windows
    if ( charliepassword != null )
    {
      kpg.initialize(2048);
      KeyPair charliekp = kpg.generateKeyPair();
      exportKeyPair( 2, charliekp, "charlie", charliepassword );
    }
    
    // Save the key rings to files
    saveKeyRings();
  }

  
  /**
   * @param args the command line arguments
   */
  public static char[] makeWindowsPasswordGuard()
  {
    try
    {
      PublicKey pubk;
      BigInteger serial;
      WindowsCertificateGenerator wcg = new WindowsCertificateGenerator();
      
      serial = wcg.generateSelfSignedCertificate(
              "CN=My key pair for guarding passwords",
              "qyouti-" + UUID.randomUUID().toString(),
              MS_ENH_RSA_AES_PROV,
              PROV_RSA_AES,
              true,
              2048,
              CRYPT_USER_PROTECTED
      );
      if (serial == null)
      {
        System.out.println("Failed to make certificate.");
        return null;
      }
      else
      {
        System.out.println("Serial number = " + serial.toString(16) );
        System.out.println("As long = " + Long.toHexString( serial.longValue() ) );        
      }

      pubk = wcg.getPublickey();
      char[] p = EncryptedCompositeFile.generateRandomPassphrase();
      Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      cipher.init( Cipher.ENCRYPT_MODE, pubk );
      byte[] crypt = cipher.doFinal( new String(p).getBytes() );
      FileOutputStream out = new FileOutputStream("demo/windowsprotectedpasswords.bin");
      out.write(crypt);
      out.close();

      return p;
    }
    catch (Exception e)
    {
      System.out.println( "Unable to create Windows password guard." );
      e.printStackTrace(System.out);
      return null;
    }

  }
  
  
  /**
   * Run the demo.
   * @param args No arguments used.
   * @throws Exception 
   */
  public static void main(
          String[] args)
          throws Exception
  {
    AliceBobCharlieGenKeys inst = new AliceBobCharlieGenKeys();
    inst.run();
  }
}
