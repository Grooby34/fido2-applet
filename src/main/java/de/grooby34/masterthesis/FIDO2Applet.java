package de.grooby34.masterthesis;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import org.apache.commons.codec.binary.Hex;

/**
 * FIDO2 JavaCard Applet with complete CBOR parsing implementation
 * <p>
 * This applet implements a FIDO2 authenticator on a JavaCard Secure Element
 * with proper CBOR parsing and encoding for CTAP2 protocol compliance.
 *
 * @author Tobias Franke
 * @version 2.0 - Complete CBOR implementation for master's thesis
 * @since JavaCard 3.0.5
 */
public class FIDO2Applet extends Applet {

    // CTAP2 Command Constants
    private static final byte CTAP2_MAKE_CREDENTIAL = 0x01;
    private static final byte CTAP2_GET_ASSERTION = 0x02;
    private static final byte CTAP2_GET_INFO = 0x04;
    private static final byte CTAP2_CLIENT_PIN = 0x06;
    private static final byte CTAP2_RESET = 0x07;

    // CTAP2 Error Codes
    private static final short CTAP2_OK = 0x00;
    private static final short CTAP2_ERR_INVALID_COMMAND = 0x01;
    private static final short CTAP2_ERR_INVALID_PARAMETER = 0x02;
    private static final short CTAP2_ERR_INVALID_LENGTH = 0x03;
    private static final short CTAP2_ERR_INVALID_SEQ = 0x04;
    private static final short CTAP2_ERR_TIMEOUT = 0x05;
    private static final short CTAP2_ERR_CHANNEL_BUSY = 0x06;
    private static final short CTAP2_ERR_LOCK_REQUIRED = 0x0A;
    private static final short CTAP2_ERR_INVALID_CHANNEL = 0x0B;
    private static final short CTAP2_ERR_CBOR_UNEXPECTED_TYPE = 0x11;
    private static final short CTAP2_ERR_INVALID_CBOR = 0x12;
    private static final short CTAP2_ERR_MISSING_PARAMETER = 0x14;
    private static final short CTAP2_ERR_LIMIT_EXCEEDED = 0x15;
    private static final short CTAP2_ERR_UNSUPPORTED_EXTENSION = 0x16;
    private static final short CTAP2_ERR_CREDENTIAL_EXCLUDED = 0x19;
    private static final short CTAP2_ERR_PROCESSING = 0x21;
    private static final short CTAP2_ERR_INVALID_CREDENTIAL = 0x22;
    private static final short CTAP2_ERR_USER_ACTION_PENDING = 0x23;
    private static final short CTAP2_ERR_OPERATION_PENDING = 0x24;
    private static final short CTAP2_ERR_NO_OPERATIONS = 0x25;
    private static final short CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26;
    private static final short CTAP2_ERR_OPERATION_DENIED = 0x27;
    private static final short CTAP2_ERR_KEY_STORE_FULL = 0x28;
    private static final short CTAP2_ERR_NO_OPERATION_PENDING = 0x2A;
    private static final short CTAP2_ERR_UNSUPPORTED_OPTION = 0x2B;
    private static final short CTAP2_ERR_INVALID_OPTION = 0x2C;
    private static final short CTAP2_ERR_KEEPALIVE_CANCEL = 0x2D;
    private static final short CTAP2_ERR_NO_CREDENTIALS = 0x2E;

    // FIDO2 Algorithm Constants
    private static final short ALG_ES256 = -7; // ECDSA P-256 with SHA-256
    private static final short ALG_RS256 = -257; // RSASSA-PKCS1-v1_5 with SHA-256
    // AAGUID for this authenticator (16 bytes)
    private static final byte[] AAGUID = {
            (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78,
            (byte) 0x9A, (byte) 0xBC, (byte) 0xDE, (byte) 0xF0,
            (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44,
            (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88
    };

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
    protected static final byte[] TXT_FIDO20 = {'F', 'I', 'D', 'O', '_', '2', '_', '0'};
    protected static final byte[] TXT_FIDO21 = {'F', 'I', 'D', 'O', '_', '2', '_', '1'};
    protected static final byte[] TXT_PLAT = {'p', 'l', 'a', 't'};
    protected static final byte[] TXT_RK = {'r', 'k'};
    protected static final byte[] TXT_UP = {'u', 'p'};
    protected static final byte[] TXT_NONE = {'n', 'o', 'n', 'e'};

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

    /**
     * Constructor for FIDOApplet2
     */
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

    /**
     * Installation method called by JCRE
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new FIDO2Applet().register();
    }

    /**
     * Main process method - handles all APDU commands
     */
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
                case CTAP2_GET_INFO:
                    processGetInfo(apdu);
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

    /**
     * Process FIDO2 makeCredential command with complete CBOR parsing
     */
    private void processMakeCredential(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

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

                            if (rpKeyLen == 2 &&
                                    rpKey[0] == 'i' && rpKey[1] == 'd') {
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
                            byte[] userKey = new byte[20];
                            short userKeyLen = cborParser.parseTextStringKey(userKey, (short) 0, (short) 12);
                            System.out.println(Hex.encodeHexString(userKey));
                            System.out.println(userKeyLen);
                            if (userKeyLen == 2 &&
                                    userKey[0] == 'i' && userKey[1] == 'd') {
                                // Found "id" field
                                userIdLength = cborParser.parseByteString(userId, (short) 0, (short) 64);
                                System.out.println(Hex.encodeHexString(userId));
                                hasUser = true;
                            } else {
                                // Skip other user fields (name, displayName)
                                cborParser.skipValue();
                            }
                        }
                        break;
                        // 6432566959585630614735706279316E64584A6C

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

                                if (algKeyLen == 3 &&
                                        algKey[0] == 'a' && algKey[1] == 'l' && algKey[2] == 'g') {
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
            sha256.update(rpId, (short) 0, rpIdLength);
            sha256.doFinal(null, (short) 0, (short) 0, rpIdHash, (short) 0);

            // Generate user ID hash for storage
            sha256.update(userId, (short) 0, userIdLength);
            sha256.doFinal(null, (short) 0, (short) 0, userIdHash, (short) 0);

            // Generate new credential ID // TODO: remove static credential id
            //randomData.generateData(credentialId, (short) 0, (short) 32);
            credentialId = new byte[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

            // Generate new key pair
            KeyPair keyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
            keyPair.genKeyPair();
            ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
            ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

            // Store credential persistently
            short credentialIndex = credentialStorage.storeCredentialPersistent(
                    credentialId, (short) 0,
                    rpIdHash, (short) 0,
                    userIdHash, (short) 0,
                    privateKey,
                    publicKey
            );

            if (credentialIndex == -1) {
                sendCTAP2Error(apdu, CTAP2_ERR_KEY_STORE_FULL);
                return;
            }

            // Create authenticator data with attested credential data
            short authDataLength = createAuthenticatorDataWithAttestedCred(
                    rpIdHash, (byte) 0x41, credentialId, publicKey, tempBuffer, (short) 0
            );

            // Create attestation object with proper CBOR encoding
            cborEncoder.init(buffer, (short) 0, (short) buffer.length);

            // Encode attestation object map with 2 entries: {fmt, authData}
            cborEncoder.encodeMapStart((short) 2);

            // "fmt": "none"
            cborEncoder.encodeTextString(TXT_FMT, (short) 0, (short) 3);
            cborEncoder.encodeTextString(TXT_NONE, (short) 0, (short) 4);

            // "authData": <authenticator data>
            cborEncoder.encodeTextString(TXT_AUTHDATA, (short) 0, (short) 8);
            cborEncoder.encodeByteString(tempBuffer, (short) 0, authDataLength);

            // "attStmt": <attestation statement>
            // cborEncoder.encodeTextString("attStmt".getBytes(), (short) 0, (short) 7);
            // encodeAttestationStatement(cborEncoder, clientDataHash, tempBuffer, authDataLength, privateKey);

            // Send successful response
            sendCTAP2Response(apdu, CTAP2_OK, buffer, (short) 0, cborEncoder.getPosition());

        } catch (Exception e) {
            sendCTAP2Error(apdu, CTAP2_ERR_PROCESSING);
        }
    }

    /**
     * Process FIDO2 getAssertion command with complete CBOR parsing
     */
    private void processGetAssertion(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        try {
            short bytesRead = apdu.setIncomingAndReceive();

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
                                            byte[]  tmpCredID = new byte[32];
                                            // Found "id" field - extract credential ID
                                            short credIdLen = cborParser.parseByteString(
                                                    tmpCredID,
                                                    //allowedCredentialIds[allowedCredentialCount],
                                                    (short) 0,
                                                    (short) 32
                                            );
                                            if (credIdLen == 32) {
                                                short writeOffset = (short)(j * 32);
                                                Util.arrayCopy(tmpCredID, (short) 0, allowedCredentialIds, writeOffset, (short)32);
                                                foundCredId = true;
                                            }
                                        } else if (credKeyLen == 4 &&
                                                credKey[0] == 't' && credKey[1] == 'y' &&
                                                credKey[2] == 'p' && credKey[3] == 'e') {
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
            sha256.update(rpId, (short) 0, rpIdLength);
            sha256.doFinal(null, (short) 0, (short) 0, rpIdHash, (short) 0);

            short credIndex = -1;

            if (hasAllowList && allowedCredentialCount > 0) {
                // Use allowList to find matching credential
                for (short i = 0; i < allowedCredentialCount; i++) {
                    byte[] tmpCredID = new byte[32];
                    short readOffset = (short)(i * 32);
                    Util.arrayCopy(allowedCredentialIds, readOffset, tmpCredID, (short)0, (short)32);

                    short foundIndex = credentialStorage.findCredentialById(
                            tmpCredID, (short) 0
                    );

                    if (foundIndex != -1) {
                        // Found a matching credential by ID
                        // Additional verification: check if credential belongs to this RP
                        // We'll do this by trying to find it in the RP's credential list
                        short[] rpCredentials = new short[10];
                        short numRpMatches = credentialStorage.findCredentialsByRpId(
                                rpIdHash, (short) 0, rpCredentials
                        );

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
                short numMatches = credentialStorage.findCredentialsByRpId(
                        rpIdHash, (short) 0, matchingCredentials
                );

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
            ECPublicKey publicKey = credentialStorage.getPublicKey(credIndex);

            // Get credential ID for response
            credentialStorage.getCredentialId(credIndex, credentialId, (short) 0);

            // Create authenticator data with attested credential data
            //short authDataLength = createAuthenticatorDataWithAttestedCred(
            //        rpIdHash, (byte) 0x01, credentialId, publicKey, tempBuffer, (short) 0
            //);

            // Use simple authenticator data (37 bytes vs 164+ bytes)
            short authDataLength = createSimpleAuthenticatorData(
                    rpIdHash, (byte) 0x01, tempBuffer, (short) 0
            );

            // Create assertion signature over authData || clientDataHash
            short signatureDataLength = (short) (authDataLength + 32);

            Util.arrayCopy(clientDataHash, (short) 0, tempBuffer, authDataLength, (short) 32);

            ecdsaSignature.init(privateKey, Signature.MODE_SIGN);
            short sigLength = ecdsaSignature.sign(tempBuffer, (short) 0, signatureDataLength,
                    signatureBuffer, (short) 0);

            // Build CBOR response
            cborEncoder.init(buffer, (short) 0, (short) buffer.length);
            cborEncoder.encodeMapStart((short) 3);

            // Field 1: credential
            cborEncoder.encodeInteger((short) 1);
            cborEncoder.encodeMapStart((short) 2);

            // credential.type = "public-key"
            cborEncoder.encodeTextString(TXT_TYPE, (short) 0, (short) 4);
            cborEncoder.encodeTextString(TXT_PUBKEY, (short) 0, (short) 10);

            // credential.id = credentialId
            cborEncoder.encodeTextString(TXT_ID, (short) 0, (short) 2);
            cborEncoder.encodeByteString(credentialId, (short) 0, (short) 32);

            // Field 2: authData
            cborEncoder.encodeInteger((short) 2);
            cborEncoder.encodeByteString(tempBuffer, (short) 0, authDataLength);

            // Field 3: signature
            cborEncoder.encodeInteger((short) 3);
            cborEncoder.encodeByteString(signatureBuffer, (short) 0, sigLength);

            // Send successful response
            sendCTAP2Response(apdu, CTAP2_OK, buffer, (short) 0, cborEncoder.getPosition());

        } catch (Exception e) {
            sendCTAP2Error(apdu, CTAP2_ERR_PROCESSING);
        }
    }

    /**
     * Process CTAP2 getInfo command
     */
    private void processGetInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        try {
            // Build getInfo response with CBOR encoding
            cborEncoder.init(buffer, (short) 0, (short) buffer.length);
            cborEncoder.encodeMapStart((short) 5);

            // Field 1: versions
            cborEncoder.encodeInteger((short) 1);
            cborEncoder.encodeArrayStart((short) 2);
            cborEncoder.encodeTextString(TXT_FIDO20, (short) 0, (short) 8);
            cborEncoder.encodeTextString(TXT_FIDO21, (short) 0, (short) 8);

            // Field 3: aaguid
            cborEncoder.encodeInteger((short) 3);
            cborEncoder.encodeByteString(AAGUID, (short) 0, (short) 16);

            // Field 4: options
            cborEncoder.encodeInteger((short) 4);
            cborEncoder.encodeMapStart((short) 3);

            // plat: false
            cborEncoder.encodeTextString(TXT_PLAT, (short) 0, (short) 4);
            cborEncoder.encodeBoolean(false);

            // rk: true (supports resident keys)
            cborEncoder.encodeTextString(TXT_RK, (short) 0, (short) 2);
            cborEncoder.encodeBoolean(true);

            // up: true (supports user presence)
            cborEncoder.encodeTextString(TXT_UP, (short) 0, (short) 2);
            cborEncoder.encodeBoolean(true);

            // Field 5: maxMsgSize
            cborEncoder.encodeInteger((short) 5);
            cborEncoder.encodeInteger((short) 1024);

            // Field 6: pinProtocols
            cborEncoder.encodeInteger((short) 6);
            cborEncoder.encodeArrayStart((short) 1);
            cborEncoder.encodeInteger((short) 1); // PIN protocol v1

            // Send successful response
            sendCTAP2Response(apdu, CTAP2_OK, buffer, (short) 0, cborEncoder.getPosition());

        } catch (Exception e) {
            sendCTAP2Error(apdu, CTAP2_ERR_PROCESSING);
        }
    }

    /**
     * Process CTAP2 reset command
     */
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

    /**
     * Create authenticator data with attested credential data for makeCredential
     */
    private short createAuthenticatorDataWithAttestedCred(
            byte[] rpIdHash, byte flags, byte[] credId, ECPublicKey pubKey,
            byte[] output, short offset) {

        short pos = offset;

        // RP ID hash (32 bytes)
        Util.arrayCopy(rpIdHash, (short) 0, output, pos, (short) 32);
        pos += 32;

        // Flags (1 byte)
        output[pos++] = flags;

        // Signature counter (4 bytes, big-endian)
        output[pos++] = 0x00;
        output[pos++] = 0x00;
        output[pos++] = 0x00;
        output[pos++] = 0x01;

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

    /**
     * Create simple authenticator data for getAssertion (without attested credential data)
     */
    private short createSimpleAuthenticatorData(
            byte[] rpIdHash, byte flags, byte[] output, short offset) {

        short pos = offset;

        // RP ID hash (32 bytes)
        Util.arrayCopy(rpIdHash, (short) 0, output, pos, (short) 32);
        pos += 32;

        // Flags (1 byte)
        output[pos++] = flags;

        // Signature counter (4 bytes, big-endian) - increment for each assertion
        output[pos++] = 0x00;
        output[pos++] = 0x00;
        output[pos++] = 0x00;
        output[pos++] = 0x01;

        return (short) (pos - offset);
    }

    /**
     * Encode COSE public key format for P-256
     */
    private short encodeCOSEPublicKey(ECPublicKey pubKey, byte[] output, short offset) {
        byte[] pubKeyData = new byte[65]; // Uncompressed point format
        short pubKeyLength = pubKey.getW(pubKeyData, (short) 0);

        if (pubKeyLength != 65 || pubKeyData[0] != 0x04) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Use encoder to create COSE key map
        CBOREncoder keyEncoder = new CBOREncoder(output, offset, (short) (output.length - offset));

        // COSE Key map with 5 fields
        keyEncoder.encodeMapStart((short) 5);

        // kty: 2 (EC2)
        keyEncoder.encodeInteger((short) 1);
        keyEncoder.encodeInteger((short) 2);

        // alg: -7 (ES256)
        keyEncoder.encodeInteger((short) 3);
        keyEncoder.encodeInteger((short) -7);

        // crv: 1 (P-256)
        keyEncoder.encodeInteger((short) -1);
        keyEncoder.encodeInteger((short) 1);

        // x coordinate (32 bytes)
        keyEncoder.encodeInteger((short) -2);
        keyEncoder.encodeByteString(pubKeyData, (short) 1, (short) 32);

        // y coordinate (32 bytes)
        keyEncoder.encodeInteger((short) -3);
        keyEncoder.encodeByteString(pubKeyData, (short) 33, (short) 32);

        return (short) (keyEncoder.getPosition() - offset);
    }

    /**
     * Create attestation statement for "packed" format
     */
    private void encodeAttestationStatement(CBOREncoder encoder, byte[] clientDataHash,
                                            byte[] authData, short authDataLength, ECPrivateKey privateKey) {
        // "packed" format with self-attestation
        encoder.encodeMapStart((short) 2);

        // "alg": -7 (ES256)
        encoder.encodeTextString(TXT_ALG, (short) 0, (short) 3);
        encoder.encodeInteger((short) -7);

        // "sig": signature over authData || clientDataHash
        encoder.encodeTextString(TXT_SIG, (short) 0, (short) 3);

        // Create data to sign: authData || clientDataHash
        short signDataLength = (short) (authDataLength + 32);
        Util.arrayCopy(authData, (short) 0, tempBuffer, (short) 256, authDataLength);
        Util.arrayCopy(clientDataHash, (short) 0, tempBuffer, (short) (256 + authDataLength), (short) 32);

        // Sign the data
        ecdsaSignature.init(privateKey, Signature.MODE_SIGN);
        short sigLength = ecdsaSignature.sign(tempBuffer, (short) 256, signDataLength,
                signatureBuffer, (short) 0);

        encoder.encodeByteString(signatureBuffer, (short) 0, sigLength);
    }

    /**
     * Send CTAP2 response with status code
     */
    private void sendCTAP2Response(APDU apdu, short status, byte[] data, short offset, short length) {
        byte[] buffer = apdu.getBuffer();

        // Move data to start of buffer if needed
        if (offset != 0) {
            Util.arrayCopy(data, offset, buffer, (short) 0, length);
        }

        // Prepend status code
        if (length > 0) {
            Util.arrayCopyNonAtomic(buffer, (short) 0, buffer, (short) 1, length);
        }
        buffer[0] = (byte) status;

        apdu.setOutgoingAndSend((short) 0, (short) (length + 1));
    }

    /**
     * Send CTAP2 error response
     */
    private void sendCTAP2Error(APDU apdu, short errorCode) {
        byte[] buffer = apdu.getBuffer();
        buffer[0] = (byte) errorCode;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    /**
     * Compute hash for credential lookup
     */
    private void computeHash(byte[] input, short inputOffset, short inputLength,
                             byte[] output, short outputOffset) {
        sha256.update(input, inputOffset, inputLength);
        sha256.doFinal(null, (short) 0, (short) 0, output, outputOffset);
    }

    /**
     * Generate secure random credential ID
     */
    private void generateCredentialId(byte[] output, short offset) {
        randomData.generateData(output, offset, (short) 32);
    }
}