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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
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

/**
 * Generates RSA PGPPublicKey/PGPSecretKey pairs for demos.
 */
public class GenKeys
{

  PGPSecretKeyRingCollection[] secringcoll = new PGPSecretKeyRingCollection[2];
  PGPPublicKeyRingCollection[] pubringcoll = new PGPPublicKeyRingCollection[2];
  
  
  private void createKeyRings() throws IOException, PGPException
  {
    secringcoll[0] = new PGPSecretKeyRingCollection( new ArrayList<>() );
    secringcoll[1] = new PGPSecretKeyRingCollection( new ArrayList<>() );
    pubringcoll[0] = new PGPPublicKeyRingCollection( new ArrayList<>() );
    pubringcoll[1] = new PGPPublicKeyRingCollection( new ArrayList<>() );    
  }
  
  
  private void saveKeyRings() throws IOException
  {
    FileOutputStream out;
    
    out = new FileOutputStream("demo/alice_secring.gpg");
    secringcoll[0].encode(out);
    out.close();
    
    out = new FileOutputStream("demo/alice_pubring.gpg");
    pubringcoll[0].encode(out);
    out.close();
    
    out = new FileOutputStream("demo/bob_secring.gpg");
    secringcoll[1].encode(out);
    out.close();
    
    out = new FileOutputStream("demo/bob_pubring.gpg");
    pubringcoll[1].encode(out);
    out.close();
    
    
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
    
    secringcoll[secretOut] = PGPSecretKeyRingCollection.addSecretKeyRing( secringcoll[secretOut], secretKeyRing );
    for ( int i=0; i<pubringcoll.length; i++ )
      pubringcoll[i] = PGPPublicKeyRingCollection.addPublicKeyRing( pubringcoll[i], keyring );
  }


  public void run()
          throws Exception
  {
    Security.addProvider(new BouncyCastleProvider());

    createKeyRings();
    
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");

    kpg.initialize(1024);
    KeyPair alicekp = kpg.generateKeyPair();
    kpg.initialize(1024);
    KeyPair bobkp = kpg.generateKeyPair();

    exportKeyPair( 0, alicekp, "alice", "alice".toCharArray() );
    exportKeyPair( 1, bobkp, "bob", "bob".toCharArray() );
    
    saveKeyRings();
  }

  public static void main(
          String[] args)
          throws Exception
  {
    GenKeys inst = new GenKeys();
    inst.run();
  }
}
