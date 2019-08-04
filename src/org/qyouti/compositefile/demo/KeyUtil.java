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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Iterator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;

/**
 *
 * @author jon
 */
public class KeyUtil
{
  File secfile, pubfile;
  PGPSecretKeyRingCollection secringcoll;
  PGPPublicKeyRingCollection pubringcoll;
  KeyFingerPrintCalculator fpcalc = new BcKeyFingerprintCalculator();
  BcPBESecretKeyDecryptorBuilder seckeydecbuilder = new BcPBESecretKeyDecryptorBuilder(  new BcPGPDigestCalculatorProvider() );

  public KeyUtil( File secfile, File pubfile ) throws IOException, PGPException
  {
    this.secfile = secfile;
    this.pubfile = pubfile;
    FileInputStream fin;
    fin = new FileInputStream( secfile );
    secringcoll = new PGPSecretKeyRingCollection( fin, fpcalc );
    fin = new FileInputStream( pubfile );
    pubringcoll = new PGPPublicKeyRingCollection( fin, fpcalc );
  }
  
  public PGPPublicKey getPublicKey( String name ) throws PGPException
  {
    Iterator<PGPPublicKeyRing> it = pubringcoll.getKeyRings(name);
    PGPPublicKeyRing keyring;
    if ( !it.hasNext() )
      return null;
    keyring = it.next();
    if ( it.hasNext() )
      return null;
    return keyring.getPublicKey();
  }
  
  public PGPPrivateKey getPrivateKey( String name, char[] passphrase ) throws PGPException
  {
    Iterator<PGPSecretKeyRing> it = secringcoll.getKeyRings(name);
    PGPSecretKeyRing keyring;
    if ( !it.hasNext() )
      return null;
    keyring = it.next();
    if ( it.hasNext() )
      return null;
    PBESecretKeyDecryptor dec = seckeydecbuilder.build(passphrase);
    return keyring.getSecretKey().extractPrivateKey(dec);
  }
  
}
