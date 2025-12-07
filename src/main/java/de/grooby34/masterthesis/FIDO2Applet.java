package de.grooby34.masterthesis;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;

/**
 * FIDO2 JavaCard Applet with complete CBOR parsing implementation
 *
 * <p>This applet implements a FIDO2 authenticator on a JavaCard Secure Element with proper CBOR
 * parsing and encoding for CTAP2 protocol compliance.
 *
 * @author Tobias Franke
 * @version 2.0 - Complete CBOR implementation for master's thesis
 * @since JavaCard 3.0.5
 */
public class FIDO2Applet extends Applet {

  // String constants
  protected static final byte[] TXT_FMT = {'f', 'm', 't'};
  protected static final byte[] TXT_PACKED = {'p', 'a', 'c', 'k', 'e', 'd'};
  protected static final byte[] TXT_AUTHDATA = {'a', 'u', 't', 'h', 'D', 'a', 't', 'a'};
  protected static final byte[] TXT_ATTSTMS = {'a', 't', 't', 'S', 't', 'm', 't'};
  protected static final byte[] TXT_ALG = {'a', 'l', 'g'};
  protected static final byte[] TXT_SIG = {'s', 'i', 'g'};
  protected static final byte[] TXT_TYPE = {'t', 'y', 'p', 'e'};
  protected static final byte[] TXT_PUBKEY = {'p', 'u', 'b', 'l', 'i', 'c', '-', 'k', 'e', 'y'};
  protected static final byte[] TXT_ID = {'i', 'd'};
  protected static final byte[] TXT_NONE = {'n', 'o', 'n', 'e'};
  // CTAP2 Command Constants
  private static final byte CTAP2_MAKE_CREDENTIAL = 0x01;
  private static final byte CTAP2_GET_ASSERTION = 0x02;
  private static final byte CTAP2_RESET = 0x07;
  // CTAP2 Error Codes
  private static final short CTAP2_OK = 0x00;
  private static final short CTAP2_ERR_INVALID_COMMAND = 0x01;
  private static final short CTAP2_ERR_INVALID_CBOR = 0x12;
  private static final short CTAP2_ERR_MISSING_PARAMETER = 0x14;
  private static final short CTAP2_ERR_PROCESSING = 0x21;
  private static final short CTAP2_ERR_INVALID_CREDENTIAL = 0x22;
  private static final short CTAP2_ERR_KEY_STORE_FULL = 0x28;
  private static final short CTAP2_ERR_NO_CREDENTIALS = 0x2E;
  // FIDO2 Algorithm Constants
  private static final short ALG_ES256 = -7; // ECDSA P-256 with SHA-256

  // AAGUID for this authenticator (16 bytes)
  private static final byte[] AAGUID = {
    (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78,
    (byte) 0x9A, (byte) 0xBC, (byte) 0xDE, (byte) 0xF0,
    (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44,
    (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88
  };
  // Instance variables
  private CBORParser cborParser;
  private CBOREncoder cborEncoder;
  private CredentialStoragePersistent credentialStorage;
  private RandomData randomData;
  private MessageDigest sha256;
  private Signature ecdsaSignature;
  // Temporary buffers
  private byte[] tempBuffer;
  private byte[] clientDataHash;
  private byte[] rpIdHash;
  private byte[] userIdHash;
  private byte[] credentialId;
  private byte[] signatureBuffer;

  /** Constructor for FIDOApplet2 */
  public FIDO2Applet() {
    // Initialize components
    credentialStorage = new CredentialStoragePersistent();

    // Initialize crypto objects
    randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    ecdsaSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

    // Initialize buffers
    tempBuffer = new byte[512];
    clientDataHash = new byte[32];
    rpIdHash = new byte[32];
    userIdHash = new byte[32];
    credentialId = new byte[32];
    signatureBuffer = new byte[72];

    // Initialize CBOR components
    cborParser = new CBORParser();
    cborEncoder = new CBOREncoder();
  }

  /** Installation method called by JCRE */
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new FIDO2Applet().register();
  }

  /** Main process method - handles all APDU commands */
  public void process(APDU apdu) {
    if (selectingApplet()) {
      return;
    }

    byte[] buffer = apdu.getBuffer();
    byte cla = buffer[ISO7816.OFFSET_CLA];
    byte ins = buffer[ISO7816.OFFSET_INS];

    // Check for CTAP2 commands (CLA = 0x80)
    if (cla == (byte) 0x80) {
      switch (ins) {
        case CTAP2_MAKE_CREDENTIAL:
          processMakeCredential(apdu);
          break;
        case CTAP2_GET_ASSERTION:
          processGetAssertion(apdu);
          break;
        case CTAP2_RESET:
          processReset(apdu);
          break;
        default:
          sendCTAP2Error(apdu, CTAP2_ERR_INVALID_COMMAND);
          break;
      }
    } else {
      ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }
  }

  /** Process FIDO2 makeCredential command with complete CBOR parsing */
  private void processMakeCredential(APDU apdu) {
    byte[] buffer = apdu.getBuffer();

    JCSystem.beginTransaction();
    try {
      // Get command data
      short bytesRead = apdu.setIncomingAndReceive();

      // Initialize CBOR parser with received data
      cborParser.init(buffer, ISO7816.OFFSET_CDATA, bytesRead);

      // Parse CTAP2 makeCredential parameters according to spec
      if (!cborParser.expectMapStart()) {
        sendCTAP2Error(apdu, CTAP2_ERR_INVALID_CBOR);
        return;
      }

      // Extract required parameters
      boolean hasClientDataHash = false;
      boolean hasRp = false;
      boolean hasUser = false;
      boolean hasPubKeyCredParams = false;

      byte[] rpId = new byte[64];
      short rpIdLength = 0;
      byte[] userId = new byte[64];
      short userIdLength = 0;

      // Parse map fields
      short mapLength = cborParser.getLastMapLength();
      for (short i = 0; i < mapLength; i++) {
        short key = cborParser.parseIntegerKey();

        switch (key) {
          case 1: // clientDataHash
            if (cborParser.parseByteString(clientDataHash, (short) 0, (short) 32) == 32) {
              hasClientDataHash = true;
            }
            break;

          case 2: // rp
            if (!cborParser.expectMapStart()) {
              sendCTAP2Error(apdu, CTAP2_ERR_INVALID_CBOR);
              return;
            }

            // Parse RP map
            short rpMapLength = cborParser.getLastMapLength();
            for (short j = 0; j < rpMapLength; j++) {
              byte[] rpKey = new byte[8];
              short rpKeyLen = cborParser.parseTextStringKey(rpKey, (short) 0, (short) 8);

              if (rpKeyLen == 2 && rpKey[0] == 'i' && rpKey[1] == 'd') {
                // Found "id" field
                rpIdLength = cborParser.parseTextString(rpId, (short) 0, (short) 64);
                hasRp = true;
              } else {
                // Skip other RP fields (name, icon)
                cborParser.skipValue();
              }
            }
            break;

          case 3: // user
            if (!cborParser.expectMapStart()) {
              sendCTAP2Error(apdu, CTAP2_ERR_INVALID_CBOR);
              return;
            }

            // Parse user map - extract user.id
            short userMapLength = cborParser.getLastMapLength();
            for (short j = 0; j < userMapLength; j++) {
              byte[] userKey = new byte[12];
              short userKeyLen = cborParser.parseTextStringKey(userKey, (short) 0, (short) 12);

              if (userKeyLen == 2 && userKey[0] == 'i' && userKey[1] == 'd') {
                // Found "id" field
                userIdLength = cborParser.parseByteString(userId, (short) 0, (short) 64);
                hasUser = true;
              } else {
                // Skip other user fields (name, displayName)
                cborParser.skipValue();
              }
            }
            break;

          case 4: // pubKeyCredParams
            if (!cborParser.expectArrayStart()) {
              sendCTAP2Error(apdu, CTAP2_ERR_INVALID_CBOR);
              return;
            }

            // Check if ES256 is supported
            short arrayLength = cborParser.getLastArrayLength();
            for (short j = 0; j < arrayLength; j++) {
              if (!cborParser.expectMapStart()) {
                sendCTAP2Error(apdu, CTAP2_ERR_INVALID_CBOR);
                return;
              }

              short algMapLength = cborParser.getLastMapLength();
              for (short k = 0; k < algMapLength; k++) {
                byte[] algKey = new byte[4];
                short algKeyLen = cborParser.parseTextStringKey(algKey, (short) 0, (short) 4);

                if (algKeyLen == 3 && algKey[0] == 'a' && algKey[1] == 'l' && algKey[2] == 'g') {
                  short algorithm = cborParser.parseInteger();
                  if (algorithm == ALG_ES256) {
                    hasPubKeyCredParams = true;
                  }
                } else {
                  cborParser.skipValue();
                }
              }
            }
            break;

          case 5: // excludeList (optional)
            // Skip exclude list for now
            cborParser.skipValue();
            break;

          case 6: // extensions (optional)
            // Skip extensions for now
            cborParser.skipValue();
            break;

          case 7: // options (optional)
            // Skip options for now
            cborParser.skipValue();
            break;

          default:
            // Skip unknown fields
            cborParser.skipValue();
            break;
        }
      }

      // Validate required parameters
      if (!hasClientDataHash || !hasRp || !hasUser || !hasPubKeyCredParams) {
        sendCTAP2Error(apdu, CTAP2_ERR_MISSING_PARAMETER);
        return;
      }

      // Generate RP ID hash
      sha256.doFinal(rpId, (short) 0, rpIdLength, rpIdHash, (short) 0);

      // Generate user ID hash for storage
      sha256.doFinal(userId, (short) 0, userIdLength, userIdHash, (short) 0);

      // Generate new credential ID
      randomData.generateData(credentialId, (short) 0, (short) 32);

      // Generate new key pair
      KeyPair keyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
      keyPair.genKeyPair();
      ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
      ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

      // Store credential persistently
      short credentialIndex =
          credentialStorage.storeCredentialPersistent(
              credentialId,
              (short) 0,
              rpIdHash,
              (short) 0,
              userIdHash,
              (short) 0,
              privateKey,
              publicKey);

      if (credentialIndex == -1) {
        sendCTAP2Error(apdu, CTAP2_ERR_KEY_STORE_FULL);
        return;
      }

      // Create authenticator data with attested credential data
      short authDataLength =
          createAuthenticatorDataWithAttestedCred(
              rpIdHash,
              (byte) 0x45,
              credentialId,
              publicKey,
              credentialIndex,
              tempBuffer,
              (short) 0);

      // Create attestation object with proper CBOR encoding
      cborEncoder.init(buffer, (short) 0, (short) buffer.length);

      // Encode attestation object map
      cborEncoder.encodeNoneAttestationObject(tempBuffer, authDataLength);

      // "attStmt": <attestation statement>
      // cborEncoder.encodeTextString("attStmt".getBytes(), (short) 0, (short) 7);
      // encodeAttestationStatement(cborEncoder, clientDataHash, tempBuffer, authDataLength,
      // privateKey);

      JCSystem.commitTransaction();

      // Send successful response
      sendCTAP2Response(
          apdu, CTAP2_OK, cborEncoder.getBuffer(), (short) 0, cborEncoder.getPosition());

    } catch (Exception e) {
      JCSystem.abortTransaction();
      sendCTAP2Error(apdu, CTAP2_ERR_PROCESSING);
    }
  }

  /** Process FIDO2 getAssertion command with complete CBOR parsing */
  private void processGetAssertion(APDU apdu) {
    byte[] buffer = apdu.getBuffer();

    try {
      short bytesRead = apdu.setIncomingAndReceive();

      JCSystem.beginTransaction();

      // Initialize CBOR parser
      cborParser.init(buffer, ISO7816.OFFSET_CDATA, bytesRead);
      // Parse CTAP2 getAssertion parameters
      if (!cborParser.expectMapStart()) {
        sendCTAP2Error(apdu, CTAP2_ERR_INVALID_CBOR);
        return;
      }

      // Extract required parameters
      boolean hasRpId = false;
      boolean hasClientDataHash = false;
      boolean hasAllowList = false;
      byte[] rpId = new byte[64];
      short rpIdLength = 0;

      // Storage for allowList credential IDs
      byte[] allowedCredentialIds = new byte[10 * 32]; // Support up to 10 allowed credentials
      short allowedCredentialCount = 0;

      // Parse map fields
      short mapLength = cborParser.getLastMapLength();
      for (short i = 0; i < mapLength; i++) {
        short key = cborParser.parseIntegerKey();

        switch (key) {
          case 1: // rpId
            rpIdLength = cborParser.parseTextString(rpId, (short) 0, (short) 64);
            hasRpId = true;
            break;

          case 2: // clientDataHash
            if (cborParser.parseByteString(clientDataHash, (short) 0, (short) 32) == 32) {
              hasClientDataHash = true;
            }
            break;

          case 3: // allowList (optional)
            if (cborParser.expectArrayStart()) {
              hasAllowList = true;
              short allowListLength = cborParser.getLastArrayLength();

              // Parse allowList array - each entry is a credential descriptor
              for (short j = 0; j < allowListLength && allowedCredentialCount < 10; j++) {
                if (cborParser.expectMapStart()) {
                  short credDescLength = cborParser.getLastMapLength();
                  boolean foundCredId = false;

                  // Parse credential descriptor map
                  for (short k = 0; k < credDescLength; k++) {
                    byte[] credKey = new byte[4];
                    short credKeyLen = cborParser.parseTextStringKey(credKey, (short) 0, (short) 4);

                    if (credKeyLen == 2 && credKey[0] == 'i' && credKey[1] == 'd') {
                      byte[] tmpCredID = new byte[32];
                      // Found "id" field - extract credential ID
                      short credIdLen =
                          cborParser.parseByteString(
                              tmpCredID,
                              // allowedCredentialIds[allowedCredentialCount],
                              (short) 0,
                              (short) 32);
                      if (credIdLen == 32) {
                        short writeOffset = (short) (j * 32);
                        Util.arrayCopy(
                            tmpCredID, (short) 0, allowedCredentialIds, writeOffset, (short) 32);
                        foundCredId = true;
                      }
                    } else if (credKeyLen == 4
                        && credKey[0] == 't'
                        && credKey[1] == 'y'
                        && credKey[2] == 'p'
                        && credKey[3] == 'e') {
                      // Found "type" field - should be "public-key"
                      // Parse and validate the type
                      byte[] typeValue = new byte[16];
                      short typeLen = cborParser.parseTextString(typeValue, (short) 0, (short) 16);
                      // We expect "public-key" but won't enforce for compatibility
                      if (typeLen != 10) {
                        sendCTAP2Error(apdu, CTAP2_ERR_INVALID_CREDENTIAL);
                      }
                    } else {
                      // Skip unknown credential descriptor fields (like "transports")
                      cborParser.skipValue();
                    }
                  }

                  // Only increment count if we successfully extracted a credential ID
                  if (foundCredId) {
                    allowedCredentialCount++;
                  }
                } else {
                  // Invalid credential descriptor format
                  sendCTAP2Error(apdu, CTAP2_ERR_INVALID_CBOR);
                  return;
                }
              }
            } else {
              // allowList is not an array - skip it
              cborParser.skipValue();
            }
            break;

          case 5: // options (optional)
            // Skip options
            cborParser.skipValue();
            break;

          default:
            // Skip unknown fields
            cborParser.skipValue();
            break;
        }
      }

      // Validate required parameters
      if (!hasRpId || !hasClientDataHash) {
        sendCTAP2Error(apdu, CTAP2_ERR_MISSING_PARAMETER);
        return;
      }

      // Generate RP ID hash
      sha256.doFinal(rpId, (short) 0, rpIdLength, rpIdHash, (short) 0);

      short credIndex = -1;

      if (hasAllowList && allowedCredentialCount > 0) {
        // Use allowList to find matching credential
        for (short i = 0; i < allowedCredentialCount; i++) {
          byte[] tmpCredID = new byte[32];
          short readOffset = (short) (i * 32);
          Util.arrayCopy(allowedCredentialIds, readOffset, tmpCredID, (short) 0, (short) 32);

          short foundIndex = credentialStorage.findCredentialById(tmpCredID, (short) 0);

          if (foundIndex != -1) {
            // Found a matching credential by ID
            // Additional verification: check if credential belongs to this RP
            // We'll do this by trying to find it in the RP's credential list
            short[] rpCredentials = new short[10];
            short numRpMatches =
                credentialStorage.findCredentialsByRpId(rpIdHash, (short) 0, rpCredentials);

            // Check if the found credential is in the RP's list
            boolean rpMatches = false;
            for (short j = 0; j < numRpMatches; j++) {
              if (rpCredentials[j] == foundIndex) {
                rpMatches = true;
                break;
              }
            }

            if (rpMatches) {
              credIndex = foundIndex;
              break;
            }
          }
        }
      } else {
        // No allowList provided - find any matching credential by RP ID
        short[] matchingCredentials = new short[10];
        short numMatches =
            credentialStorage.findCredentialsByRpId(rpIdHash, (short) 0, matchingCredentials);

        if (numMatches > 0) {
          credIndex = matchingCredentials[0]; // Use first matching credential
        }
      }

      // Check if we found a valid credential
      if (credIndex == -1) {
        sendCTAP2Error(apdu, CTAP2_ERR_NO_CREDENTIALS);
        return;
      }

      ECPrivateKey privateKey = credentialStorage.getPrivateKey(credIndex);

      // Get credential ID for response
      credentialStorage.getCredentialId(credIndex, credentialId, (short) 0);

      // Use simple authenticator data (37 bytes vs 164+ bytes)
      short authDataLength =
          createSimpleAuthenticatorData(rpIdHash, (byte) 0x01, credIndex, tempBuffer, (short) 0);

      // Create assertion signature over authData || clientDataHash
      short signatureDataLength = (short) (authDataLength + 32);
      Util.arrayCopy(clientDataHash, (short) 0, tempBuffer, authDataLength, (short) 32);
      ecdsaSignature.init(privateKey, Signature.MODE_SIGN);

      short sigLength =
          ecdsaSignature.sign(
              tempBuffer, (short) 0, signatureDataLength, signatureBuffer, (short) 0);

      // Build CBOR response
      cborEncoder.init(buffer, (short) 0, (short) buffer.length);
      cborEncoder.encodeAssertionResponse(
          credentialId, tempBuffer, authDataLength, signatureBuffer, sigLength);

      JCSystem.commitTransaction();

      // Send successful response
      sendCTAP2Response(
          apdu, CTAP2_OK, cborEncoder.getBuffer(), (short) 0, cborEncoder.getPosition());

    } catch (Exception e) {
      JCSystem.abortTransaction();

      sendCTAP2Error(apdu, CTAP2_ERR_PROCESSING);
    }
  }

  /** Process CTAP2 reset command */
  private void processReset(APDU apdu) {
    try {
      // Clear all stored credentials
      credentialStorage.reset();

      // Send success response
      byte[] buffer = apdu.getBuffer();
      sendCTAP2Response(apdu, CTAP2_OK, buffer, (short) 0, (short) 0);

    } catch (Exception e) {
      sendCTAP2Error(apdu, CTAP2_ERR_PROCESSING);
    }
  }

  /** Create authenticator data with attested credential data for makeCredential */
  private short createAuthenticatorDataWithAttestedCred(
      byte[] rpIdHash,
      byte flags,
      byte[] credId,
      ECPublicKey pubKey,
      short credentialIndex,
      byte[] output,
      short offset) {

    short pos = offset;

    // RP ID hash (32 bytes)
    Util.arrayCopy(rpIdHash, (short) 0, output, pos, (short) 32);
    pos += 32;

    // Flags (1 byte)
    output[pos++] = flags;

    // Signature counter (4 bytes, big-endian)
    credentialStorage.getAndIncrementSignatureCounter(credentialIndex, output, pos);

    // increase pos by 4 because of the addition of the signature counter
    pos += 4;

    // Attested credential data
    // AAGUID (16 bytes)
    Util.arrayCopy(AAGUID, (short) 0, output, pos, (short) 16);
    pos += 16;

    // Credential ID length (2 bytes, big-endian)
    output[pos++] = 0x00;
    output[pos++] = 0x20; // 32 bytes

    // Credential ID (32 bytes)
    Util.arrayCopy(credId, (short) 0, output, pos, (short) 32);
    pos += 32;

    // Public key in COSE format
    pos += encodeCOSEPublicKey(pubKey, output, pos);

    return (short) (pos - offset);
  }

  /** Create simple authenticator data for getAssertion (without attested credential data) */
  private short createSimpleAuthenticatorData(
      byte[] rpIdHash, byte flags, short credentialIndex, byte[] output, short offset) {

    short pos = offset;

    // RP ID hash (32 bytes)
    Util.arrayCopy(rpIdHash, (short) 0, output, pos, (short) 32);
    pos += 32;

    // Flags (1 byte)
    output[pos++] = flags;

    // Signature counter (4 bytes, big-endian) - increment for each assertion
    credentialStorage.getAndIncrementSignatureCounter(credentialIndex, output, pos);

    // increase pos by 4 because of the addition of the signature counter
    pos += 4;

    return (short) (pos - offset);
  }

  /** Encode COSE public key format for P-256 */
  private short encodeCOSEPublicKey(ECPublicKey pubKey, byte[] output, short offset) {
    byte[] pubKeyData = new byte[65]; // Uncompressed point format
    short pubKeyLength = pubKey.getW(pubKeyData, (short) 0);

    if (pubKeyLength != 65 || pubKeyData[0] != 0x04) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    CBOREncoder encoder = new CBOREncoder();

    // Use encoder to create COSE key map
    encoder.init(output, offset, (short) (output.length - offset));
    // COSE Key map with 5 fields
    encoder.encodeMapStart((short) 5);

    // kty: 2 (EC2)
    encoder.encodeInteger((short) 1);
    encoder.encodeInteger((short) 2);

    // alg: -7 (ES256)
    encoder.encodeInteger((short) 3);
    encoder.encodeInteger((short) -7);

    // crv: 1 (P-256)
    encoder.encodeInteger((short) -1);
    encoder.encodeInteger((short) 1);

    // x coordinate (32 bytes)
    encoder.encodeInteger((short) -2);
    encoder.encodeByteString(pubKeyData, (short) 1, (short) 32);

    // y coordinate (32 bytes)
    encoder.encodeInteger((short) -3);
    encoder.encodeByteString(pubKeyData, (short) 33, (short) 32);

    Util.arrayCopy(encoder.getBuffer(), (short) 0, output, (short) 0, encoder.getEncodedLength());

    return (short) (encoder.getPosition() - offset);
  }

  /** Send CTAP2 response with status code */
  private void sendCTAP2Response(APDU apdu, short status, byte[] data, short offset, short length) {
    byte[] buffer = apdu.getBuffer();

    // Move data to start of buffer if needed
    // if (offset != 0) {
    Util.arrayCopy(data, offset, buffer, (short) 0, length);
    // }

    // Prepend status code
    if (length > 0) {
      Util.arrayCopyNonAtomic(buffer, (short) 0, buffer, (short) 1, length);
    }
    buffer[0] = (byte) status;

    apdu.setOutgoingAndSend((short) 0, (short) (length + 1));
  }

  /** Send CTAP2 error response */
  private void sendCTAP2Error(APDU apdu, short errorCode) {
    byte[] buffer = apdu.getBuffer();
    buffer[0] = (byte) errorCode;
    apdu.setOutgoingAndSend((short) 0, (short) 1);
  }
}
