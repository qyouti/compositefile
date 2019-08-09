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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.UUID;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPPrivateKey;
import org.qyouti.winselfcert.WindowsCertificateGenerator;
import static org.qyouti.winselfcert.WindowsCertificateGenerator.CRYPT_USER_PROTECTED;
import static org.qyouti.winselfcert.WindowsCertificateGenerator.MS_ENH_RSA_AES_PROV;
import static org.qyouti.winselfcert.WindowsCertificateGenerator.PROV_RSA_AES;

/**
 * This creates a key pair for Charlie in the Windows CAPI service. The private key is given
 * protected status meaning the user is always prompted for permission when an application 
 * attempts to use the key and the private key cannot be exported.  The public key is exported
 * and added to Alice, Bob and Charlie's public PGP key rings.
 * 
 * @author maber01
 */
public class WindowsGenKey
{
  PGPPublicKeyRingCollection[] pubringcoll = new PGPPublicKeyRingCollection[3];
  
  private void initKeyRings() throws IOException, PGPException
  {
    FileInputStream fin;
    
    fin = new FileInputStream("demo/alice_pubring.gpg");
    pubringcoll[0] = new PGPPublicKeyRingCollection( fin, new BcKeyFingerprintCalculator() );
    fin.close();
    
    fin = new FileInputStream("demo/bob_pubring.gpg");
    pubringcoll[1] = new PGPPublicKeyRingCollection( fin, new BcKeyFingerprintCalculator() );
    fin.close();
    
    fin = new FileInputStream("demo/charlie_pubring.gpg");
    pubringcoll[2] = new PGPPublicKeyRingCollection( fin, new BcKeyFingerprintCalculator() );
    fin.close();
  }
  
  private void saveKeyRings() throws IOException
  {
    FileOutputStream out;
    
    out = new FileOutputStream("demo/alice_pubring.gpg");
    pubringcoll[0].encode(out);
    out.close();
    
    out = new FileOutputStream("demo/bob_pubring.gpg");
    pubringcoll[1].encode(out);
    out.close();
    
    out = new FileOutputStream("demo/charlie_pubring.gpg");
    pubringcoll[2].encode(out);
    out.close();    
  }
  /**
   * @param args the command line arguments
   */
  public static void main(String[] args)
  {
    WindowsGenKey inst = new WindowsGenKey();
    
    RSAPublicKey pubk;
    JcaPGPPrivateKey prik;  // wrapper around JCA private key
    BigInteger serial;

    WindowsCertificateGenerator wcg = new WindowsCertificateGenerator();
    try
    {
      inst.initKeyRings();
      
      serial = wcg.generateSelfSignedCertificate(
              "CN=Charlie",
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
        return;
      }
      else
      {
        System.out.println("Serial number = " + serial.toString(16) );
        System.out.println("As long = " + Long.toHexString( serial.longValue() ) );        
      }


      // convert the public to PGPPublicKey 
      pubk = (RSAPublicKey)wcg.getPublickey();
      RSAPublicBCPGKey rsapubkey = new RSAPublicBCPGKey( pubk.getModulus(), pubk.getPublicExponent());
      PublicKeyPacket pubpacket = new PublicKeyPacket( PublicKeyPacket.RSA_GENERAL, new Date(System.currentTimeMillis()), rsapubkey );
      PGPPublicKey pgppublickey = new PGPPublicKey( pubpacket, new BcKeyFingerprintCalculator() );
      
      System.out.println(" Converted key id = " + Long.toHexString(pgppublickey.getKeyID()) );

      // wrap the JCA private key so it can be used in bouncy castle
      // There is a problem with passing in a keyid derived from the Windows CAPI
      // serial number. The public key has a 'natural' id which is calculated from
      // its fingerprint. Use that.
      prik = new JcaPGPPrivateKey( pgppublickey.getKeyID(), wcg.getPrivatekey() );
      
      
      //BcPGPKeyConverter conv = new BcPGPKeyConverter();
      //PGPPublicKey pgppublickey = conv.getPGPPublicKey(PublicKeyAlgorithmTags.RSA_GENERAL, null,  );
              
      // Add ID and sign it with own (wrapped JCA) private key.
      JcaPGPContentSignerBuilder signerbuilder = new JcaPGPContentSignerBuilder( pgppublickey.getAlgorithm(), HashAlgorithmTags.SHA1 );
      PGPSignatureGenerator siggen = new PGPSignatureGenerator( signerbuilder );
      siggen.init(PGPSignature.DEFAULT_CERTIFICATION, prik );
      PGPSignature certification = siggen.generateCertification( "charlie", pgppublickey );      
      PGPPublicKey signedpgppublickey = PGPPublicKey.addCertification( pgppublickey, "charlie", certification );
              
      // Put the signed public key in a key ring
      ArrayList<PGPPublicKey> keylist = new ArrayList<>();
      keylist.add(signedpgppublickey);
      PGPPublicKeyRing keyring = new PGPPublicKeyRing(keylist);
      
      // and put it in Alice's, Bob's and Charlie's public key ring collections
      for ( int i=0; i<inst.pubringcoll.length; i++ )
        inst.pubringcoll[i] = PGPPublicKeyRingCollection.addPublicKeyRing( inst.pubringcoll[i], keyring );
      
      inst.saveKeyRings();
    }
    catch (Exception e)
    {
      e.printStackTrace(System.out);
    }

  }
  
}
