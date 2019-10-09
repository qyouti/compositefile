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

import java.security.PrivateKey;
import java.security.Provider;
import java.util.HashMap;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;

/**
 *
 * @author maber01
 */
public class EncryptedCompositeFileUser
{
  String keyalias;
  PGPPrivateKey pgpprivatekey;
  PGPPublicKey pgppublickey;
  PGPPublicKeyRingCollection pgppubkeyringcoll;
  
  HashMap<String,PassPhraseStatus> passphrasestatusmap = new HashMap<>();

  public EncryptedCompositeFileUser(
          String keyalias, 
          PGPPrivateKey pgpprivatekey, 
          PGPPublicKey pgppublickey, 
          PGPPublicKeyRingCollection pgppubkeyringcoll 
  )
  {
    this.keyalias = keyalias;
    this.pgpprivatekey = pgpprivatekey;
    this.pgppublickey = pgppublickey;
    this.pgppubkeyringcoll = pgppubkeyringcoll;
  }

  public String getKeyalias()
  {
    return keyalias;
  }

  public PGPPrivateKey getPgpprivatekey()
  {
    return pgpprivatekey;
  }

  public PGPPublicKey getPgppublickey()
  {
    return pgppublickey;
  }
  
  public PGPPublicKey getOtherPGPPublicKey( long id ) throws PGPException
  {
    if ( pgppubkeyringcoll == null )
      return null;
    return pgppubkeyringcoll.getPublicKey( id );
  }
  
  public void setPassPhraseStatus( String canonicalpath, int status )
  {
    PassPhraseStatus pps = passphrasestatusmap.get(canonicalpath);
    if ( pps == null )
    {
      pps = new PassPhraseStatus();
      passphrasestatusmap.put(canonicalpath,pps);
    }
    pps.status = status;
  }
  
  public void setPassPhrase( String canonicalpath, char[] passphrase )
  {
    PassPhraseStatus pps = passphrasestatusmap.get(canonicalpath);
    if ( pps == null )
    {
      pps = new PassPhraseStatus();
      passphrasestatusmap.put(canonicalpath,pps);
    }
    pps.passphrase = passphrase;
  }
  
  public int getPassPhraseStatus( String canonicalpath )
  {
    PassPhraseStatus pps = passphrasestatusmap.get(canonicalpath);
    if ( pps == null )
      return EncryptedCompositeFile.UNKNOWN_PASS_STATUS;
    return pps.status;
  }
  
  public char[] getPassPhrase( String canonicalpath )
  {
    PassPhraseStatus pps = passphrasestatusmap.get(canonicalpath);
    if ( pps == null )
      return null;
    return pps.passphrase;
  }
  
  class PassPhraseStatus
  {
    int status = EncryptedCompositeFile.UNKNOWN_PASS_STATUS;
    char[] passphrase = null;    
  }
}
