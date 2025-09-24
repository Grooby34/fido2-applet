package de.grooby34.masterthesis;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;

/**
 * Persistent Credential Storage for FIDO2 JavaCard Applet
 * <p>
 * Manages long-term storage of FIDO2 credentials in JavaCard's persistent memory.
 * Optimized for space efficiency and fast credential lookup operations.
 * <p>
 * Storage format per credential:
 * - 32 bytes: Credential ID
 * - 32 bytes: RP ID hash
 * - 32 bytes: User ID hash
 * - 32 bytes: Private key (P-256)
 * - 64 bytes: Public key (P-256, uncompressed)
 * - 4 bytes: Signature counter (big-endian)
 * - 1 byte: Status flags
 * Total: 197 bytes per credential
 *
 * @author Tobias Franke
 * @version 1.0
 */
public class CredentialStoragePersistent {

    // Storage constants
    private static final short CREDENTIAL_SIZE = 197;
    private static final short MAX_CREDENTIALS = 100; // Adjust based on available EEPROM
    private static final short TOTAL_STORAGE_SIZE = (short) (MAX_CREDENTIALS * CREDENTIAL_SIZE);

    // Offsets within each credential record
    private static final short OFFSET_CREDENTIAL_ID = 0;     // 32 bytes
    private static final short OFFSET_RP_ID_HASH = 32;       // 32 bytes  
    private static final short OFFSET_USER_ID_HASH = 64;     // 32 bytes
    private static final short OFFSET_PRIVATE_KEY = 96;      // 32 bytes
    private static final short OFFSET_PUBLIC_KEY = 128;      // 64 bytes
    private static final short OFFSET_SIGN_COUNTER = 192;   // 4 bytes
    private static final short OFFSET_STATUS_FLAGS = 196;   // 1 byte

    // Status flags
    private static final byte STATUS_EMPTY = 0x00;
    private static final byte STATUS_ACTIVE = 0x01;
    private static final byte STATUS_DISABLED = 0x02;

    // Persistent storage arrays
    private byte[] credentialStorage;
    private boolean isInitialized;

    /**
     * Constructor - initializes persistent storage
     */
    public CredentialStoragePersistent() {
        // Allocate persistent memory for credential storage
        credentialStorage = new byte[TOTAL_STORAGE_SIZE];
        isInitialized = false;
        initializeStorage();
    }

    /**
     * Initialize storage by marking all slots as empty
     */
    private void initializeStorage() {
        if (!isInitialized) {
            // Mark all credential slots as empty
            for (short i = 0; i < MAX_CREDENTIALS; i++) {
                short statusOffset = (short) (i * CREDENTIAL_SIZE + OFFSET_STATUS_FLAGS);
                credentialStorage[statusOffset] = STATUS_EMPTY;

                // Initialize signature counter to 0
                short counterOffset = (short) (i * CREDENTIAL_SIZE + OFFSET_SIGN_COUNTER);
                credentialStorage[counterOffset] = 0x00;
                credentialStorage[(short) (counterOffset + 1)] = 0x00;
                credentialStorage[(short) (counterOffset + 2)] = 0x00;
                credentialStorage[(short) (counterOffset + 3)] = 0x00;
            }
            isInitialized = true;
        }
    }

    /**
     * Store a new credential persistently
     *
     * @param credentialId Credential ID (32 bytes)
     * @param credIdOffset Offset in credential ID buffer
     * @param rpIdHash     RP ID hash (32 bytes)
     * @param rpIdOffset   Offset in RP ID hash buffer
     * @param userIdHash   User ID hash (32 bytes)
     * @param userIdOffset Offset in user ID hash buffer
     * @param privateKey   EC private key to store
     * @param publicKey    EC public key to store
     * @return Index of stored credential, or -1 if storage is full
     */
    public short storeCredentialPersistent(byte[] credentialId, short credIdOffset,
                                           byte[] rpIdHash, short rpIdOffset,
                                           byte[] userIdHash, short userIdOffset,
                                           ECPrivateKey privateKey, ECPublicKey publicKey) {
        // Find empty slot
        short freeSlot = findEmptySlot();
        if (freeSlot == -1) {
            return -1; // Storage full
        }

        short baseOffset = (short) (freeSlot * CREDENTIAL_SIZE);

        // Store credential ID
        Util.arrayCopy(credentialId, credIdOffset, credentialStorage,
                (short) (baseOffset + OFFSET_CREDENTIAL_ID), (short) 32);

        // Store RP ID hash
        Util.arrayCopy(rpIdHash, rpIdOffset, credentialStorage,
                (short) (baseOffset + OFFSET_RP_ID_HASH), (short) 32);

        // Store user ID hash
        Util.arrayCopy(userIdHash, userIdOffset, credentialStorage,
                (short) (baseOffset + OFFSET_USER_ID_HASH), (short) 32);

        // Store private key (extract S parameter)
        byte[] privateKeyData = new byte[32];
        short privKeyLength = privateKey.getS(privateKeyData, (short) 0);
        if (privKeyLength == 32) {
            Util.arrayCopy(privateKeyData, (short) 0, credentialStorage,
                    (short) (baseOffset + OFFSET_PRIVATE_KEY), (short) 32);
        }

        // Store public key (extract W parameter - uncompressed point)
        byte[] publicKeyData = new byte[65];
        short pubKeyLength = publicKey.getW(publicKeyData, (short) 0);
        if (pubKeyLength == 65 && publicKeyData[0] == 0x04) {
            // Store only x and y coordinates (skip 0x04 prefix)
            Util.arrayCopy(publicKeyData, (short) 1, credentialStorage,
                    (short) (baseOffset + OFFSET_PUBLIC_KEY), (short) 64);
        }

        // Initialize signature counter to 0
        short counterOffset = (short) (baseOffset + OFFSET_SIGN_COUNTER);
        credentialStorage[counterOffset] = 0x00;
        credentialStorage[(short) (counterOffset + 1)] = 0x00;
        credentialStorage[(short) (counterOffset + 2)] = 0x00;
        credentialStorage[(short) (counterOffset + 3)] = 0x00;

        // Mark slot as active
        credentialStorage[(short) (baseOffset + OFFSET_STATUS_FLAGS)] = STATUS_ACTIVE;

        return freeSlot;
    }

    /**
     * Get and increment signature counter for a credential
     *
     * @param credentialIndex Index of the credential
     */
    public void getAndIncrementSignatureCounter(short credentialIndex, byte[] out, short outOffset) {
        if (credentialIndex < 0 || credentialIndex >= MAX_CREDENTIALS) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        short baseOffset = (short) (credentialIndex * CREDENTIAL_SIZE);

        // Check if credential exists
        if (credentialStorage[(short) (baseOffset + OFFSET_STATUS_FLAGS)] != STATUS_ACTIVE) {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }

        short counterOffset = (short) (baseOffset + OFFSET_SIGN_COUNTER);

        // Read current counter value (big-endian)
        out[outOffset] = credentialStorage[counterOffset];
        out[(short)(outOffset + 1)] = credentialStorage[(short)(counterOffset + 1)];
        out[(short)(outOffset + 2)] = credentialStorage[(short)(counterOffset + 2)];
        out[(short)(outOffset + 3)] = credentialStorage[(short)(counterOffset + 3)];

        // Increment counter - work byte by byte from least significant
        // Start from the rightmost byte (index 3) and work backwards
        boolean carry = true;
        for (short i = 3; i >= 0 && carry; i--) {
            short byteIndex = (short)(counterOffset + i);
            byte currentByte = credentialStorage[byteIndex];

            if (currentByte == (byte)0xFF) {
                // Will overflow to 0x00, continue carry
                credentialStorage[byteIndex] = 0x00;
            } else {
                // No overflow, just increment and stop
                credentialStorage[byteIndex] = (byte)(currentByte + 1);
                carry = false;
            }
        }
        // Note: if carry is true after the loop, it means that all signcounter bits were already used (overflow). As this is extremely unlikely it can be ignored.
    }

    /**
     * Find credentials matching a specific RP ID hash
     *
     * @param rpIdHash      RP ID hash to search for (32 bytes)
     * @param rpIdOffset    Offset in RP ID hash buffer
     * @param resultIndices Array to store matching credential indices
     * @return Number of matching credentials found
     */
    public short findCredentialsByRpId(byte[] rpIdHash, short rpIdOffset, short[] resultIndices) {
        short matchCount = 0;

        for (short i = 0; i < MAX_CREDENTIALS && matchCount < resultIndices.length; i++) {
            short baseOffset = (short) (i * CREDENTIAL_SIZE);

            // Check if slot is active
            if (credentialStorage[(short) (baseOffset + OFFSET_STATUS_FLAGS)] != STATUS_ACTIVE) {
                continue;
            }

            // Compare RP ID hash
            if (Util.arrayCompare(rpIdHash, rpIdOffset,
                    credentialStorage, (short) (baseOffset + OFFSET_RP_ID_HASH),
                    (short) 32) == 0) {
                resultIndices[matchCount++] = i;
            }
        }

        return matchCount;
    }

    /**
     * Get private key for a specific credential index
     *
     * @param credentialIndex Index of the credential
     * @return ECPrivateKey object reconstructed from storage
     */
    public ECPrivateKey getPrivateKey(short credentialIndex) {
        if (credentialIndex < 0 || credentialIndex >= MAX_CREDENTIALS) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        short baseOffset = (short) (credentialIndex * CREDENTIAL_SIZE);

        // Check if credential exists
        if (credentialStorage[(short) (baseOffset + OFFSET_STATUS_FLAGS)] != STATUS_ACTIVE) {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }

        // Reconstruct private key
        ECPrivateKey privateKey = (ECPrivateKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);

        // Set domain parameters (P-256)
        setP256Parameters(privateKey);

        // Set S parameter
        privateKey.setS(credentialStorage, (short) (baseOffset + OFFSET_PRIVATE_KEY), (short) 32);

        return privateKey;
    }

    /**
     * Get credential ID for a specific credential index
     *
     * @param credentialIndex Index of the credential
     * @param output          Buffer to store credential ID
     * @param outputOffset    Offset in output buffer
     */
    public void getCredentialId(short credentialIndex, byte[] output, short outputOffset) {
        if (credentialIndex < 0 || credentialIndex >= MAX_CREDENTIALS) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        short baseOffset = (short) (credentialIndex * CREDENTIAL_SIZE);

        // Check if credential exists
        if (credentialStorage[(short) (baseOffset + OFFSET_STATUS_FLAGS)] != STATUS_ACTIVE) {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }

        Util.arrayCopy(credentialStorage, (short) (baseOffset + OFFSET_CREDENTIAL_ID),
                output, outputOffset, (short) 32);
    }

    /**
     * Check if a credential with specific ID already exists
     *
     * @param credentialId Credential ID to check (32 bytes)
     * @param credIdOffset Offset in credential ID buffer
     * @return Index of existing credential, or -1 if not found
     */
    public short findCredentialById(byte[] credentialId, short credIdOffset) {
        for (short i = 0; i < MAX_CREDENTIALS; i++) {
            short baseOffset = (short) (i * CREDENTIAL_SIZE);

            // Check if slot is active
            if (credentialStorage[(short) (baseOffset + OFFSET_STATUS_FLAGS)] != STATUS_ACTIVE) {
                continue;
            }

            // Compare credential ID
            if (Util.arrayCompare(credentialId, credIdOffset,
                    credentialStorage, (short) (baseOffset + OFFSET_CREDENTIAL_ID),
                    (short) 32) == 0) {
                return i;
            }
        }
        return (short) -1; // Not found
    }

    /**
     * Reset all stored credentials (CTAP2 reset operation)
     */
    public void reset() {
        // Clear all credential data
        Util.arrayFillNonAtomic(credentialStorage, (short) 0, TOTAL_STORAGE_SIZE, (byte) 0x00);

        // Re-initialize storage
        for (short i = 0; i < MAX_CREDENTIALS; i++) {
            short statusOffset = (short) (i * CREDENTIAL_SIZE + OFFSET_STATUS_FLAGS);
            credentialStorage[statusOffset] = STATUS_EMPTY;
        }
    }


    /**
     * Find first empty storage slot
     *
     * @return Index of empty slot, or -1 if storage is full
     */
    private short findEmptySlot() {
        for (short i = 0; i < MAX_CREDENTIALS; i++) {
            short statusOffset = (short) (i * CREDENTIAL_SIZE + OFFSET_STATUS_FLAGS);
            if (credentialStorage[statusOffset] == STATUS_EMPTY) {
                return i;
            }
        }
        return -1; // Storage full
    }

    /**
     * Set P-256 domain parameters for an EC key
     *
     * @param key EC key (private or public) to configure
     */
    private void setP256Parameters(ECKey key) {
        // P-256 domain parameters (NIST P-256 / secp256r1)

        // Prime field p
        byte[] p = {
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
        };

        // Coefficient a
        byte[] a = {
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC
        };

        // Coefficient b
        byte[] b = {
                (byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8,
                (byte) 0xAA, (byte) 0x3A, (byte) 0x93, (byte) 0xE7,
                (byte) 0xB3, (byte) 0xEB, (byte) 0xBD, (byte) 0x55,
                (byte) 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xBC,
                (byte) 0x65, (byte) 0x1D, (byte) 0x06, (byte) 0xB0,
                (byte) 0xCC, (byte) 0x53, (byte) 0xB0, (byte) 0xF6,
                (byte) 0x3B, (byte) 0xCE, (byte) 0x3C, (byte) 0x3E,
                (byte) 0x27, (byte) 0xD2, (byte) 0x60, (byte) 0x4B
        };

        // Generator point G
        byte[] g = {
                (byte) 0x04, // Uncompressed point indicator
                (byte) 0x6B, (byte) 0x17, (byte) 0xD1, (byte) 0xF2,
                (byte) 0xE1, (byte) 0x2C, (byte) 0x42, (byte) 0x47,
                (byte) 0xF8, (byte) 0xBC, (byte) 0xE6, (byte) 0xE5,
                (byte) 0x63, (byte) 0xA4, (byte) 0x40, (byte) 0xF2,
                (byte) 0x77, (byte) 0x03, (byte) 0x7D, (byte) 0x81,
                (byte) 0x2D, (byte) 0xEB, (byte) 0x33, (byte) 0xA0,
                (byte) 0xF4, (byte) 0xA1, (byte) 0x39, (byte) 0x45,
                (byte) 0xD8, (byte) 0x98, (byte) 0xC2, (byte) 0x96,
                // Y coordinate
                (byte) 0x4F, (byte) 0xE3, (byte) 0x42, (byte) 0xE2,
                (byte) 0xFE, (byte) 0x1A, (byte) 0x7F, (byte) 0x9B,
                (byte) 0x8E, (byte) 0xE7, (byte) 0xEB, (byte) 0x4A,
                (byte) 0x7C, (byte) 0x0F, (byte) 0x9E, (byte) 0x16,
                (byte) 0x2B, (byte) 0xCE, (byte) 0x33, (byte) 0x57,
                (byte) 0x6B, (byte) 0x31, (byte) 0x5E, (byte) 0xCE,
                (byte) 0xCB, (byte) 0xB6, (byte) 0x40, (byte) 0x68,
                (byte) 0x37, (byte) 0xBF, (byte) 0x51, (byte) 0xF5
        };

        // Order n
        byte[] n = {
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD,
                (byte) 0xA7, (byte) 0x17, (byte) 0x9E, (byte) 0x84,
                (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2,
                (byte) 0xFC, (byte) 0x63, (byte) 0x25, (byte) 0x51
        };

        // Set domain parameters
        key.setFieldFP(p, (short) 0, (short) p.length);
        key.setA(a, (short) 0, (short) a.length);
        key.setB(b, (short) 0, (short) b.length);
        key.setG(g, (short) 0, (short) g.length);
        key.setR(n, (short) 0, (short) n.length);
    }
}