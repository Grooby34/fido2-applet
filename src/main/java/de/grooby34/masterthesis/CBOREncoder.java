package de.grooby34.masterthesis;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

import static de.grooby34.masterthesis.FIDO2Applet.TXT_ALG;
import static de.grooby34.masterthesis.FIDO2Applet.TXT_ATTSTMS;
import static de.grooby34.masterthesis.FIDO2Applet.TXT_AUTHDATA;
import static de.grooby34.masterthesis.FIDO2Applet.TXT_FIDO20;
import static de.grooby34.masterthesis.FIDO2Applet.TXT_FIDO21;
import static de.grooby34.masterthesis.FIDO2Applet.TXT_FMT;
import static de.grooby34.masterthesis.FIDO2Applet.TXT_ID;
import static de.grooby34.masterthesis.FIDO2Applet.TXT_NONE;
import static de.grooby34.masterthesis.FIDO2Applet.TXT_PACKED;
import static de.grooby34.masterthesis.FIDO2Applet.TXT_PLAT;
import static de.grooby34.masterthesis.FIDO2Applet.TXT_PUBKEY;
import static de.grooby34.masterthesis.FIDO2Applet.TXT_RK;
import static de.grooby34.masterthesis.FIDO2Applet.TXT_SIG;
import static de.grooby34.masterthesis.FIDO2Applet.TXT_TYPE;
import static de.grooby34.masterthesis.FIDO2Applet.TXT_UP;


/**
 * CBOR Encoder for JavaCard FIDO2 Implementation
 * <p>
 * Lightweight CBOR encoder specifically designed for CTAP2 protocol responses
 * on JavaCard platforms with memory constraints.
 * <p>
 * Features:
 * - FIDO2-specific response encoding methods
 * - Memory-efficient encoding without dynamic allocation
 * - Support for all CBOR major types needed for CTAP2 responses
 * - Optimized for attestation objects and assertion responses
 *
 * @author Tobias Franke
 * @version 1.0
 */
public class CBOREncoder {

    // CBOR Major Types
    private static final byte MAJOR_TYPE_UNSIGNED_INT = 0x00;
    private static final byte MAJOR_TYPE_NEGATIVE_INT = 0x01;
    private static final byte MAJOR_TYPE_BYTE_STRING = 0x02;
    private static final byte MAJOR_TYPE_TEXT_STRING = 0x03;
    private static final byte MAJOR_TYPE_ARRAY = 0x04;
    private static final byte MAJOR_TYPE_MAP = 0x05;
    private static final byte MAJOR_TYPE_FLOAT_SIMPLE = 0x07;

    // CBOR Additional Information
    private static final byte AI_UINT8_FOLLOWS = 0x18;
    private static final byte AI_UINT16_FOLLOWS = 0x19;
    private static final byte AI_UINT32_FOLLOWS = 0x1A;

    // CBOR Simple Values
    private static final byte SIMPLE_FALSE = 0x14;
    private static final byte SIMPLE_TRUE = 0x15;
    private static final byte SIMPLE_NULL = 0x16;

    // Encoder state
    private byte[] buffer;
    private short position;
    private short bufferLength;

    /**
     * Default constructor
     */
    public CBOREncoder() {
        this.buffer = new byte[512];
        this.position = 0;
        this.bufferLength = 0;
    }

    /**
     * Initialize encoder with output buffer
     *
     * @param outputBuffer Output buffer for encoded data
     * @param offset       Start offset in buffer
     * @param length       Available buffer length
     */
    public void init(byte[] outputBuffer, short offset, short length) {
        Util.arrayCopy(outputBuffer, (short) 0, buffer, (short) 0, length);
        this.position = offset;
        this.bufferLength = (short) (offset + length);
    }

    /**
     * Encode a CBOR map start with specified number of key-value pairs
     *
     * @param mapSize Number of key-value pairs in the map
     */
    public void encodeMapStart(short mapSize) {
        encodeLength(MAJOR_TYPE_MAP, mapSize);
    }

    /**
     * Encode a CBOR array start with specified number of elements
     *
     * @param arraySize Number of elements in the array
     */
    public void encodeArrayStart(short arraySize) {
        encodeLength(MAJOR_TYPE_ARRAY, arraySize);
    }

    /**
     * Encode an unsigned integer value
     *
     * @param value Integer value to encode (must be non-negative)
     */
    public void encodeInteger(short value) {
        if (value >= 0) {
            encodeLength(MAJOR_TYPE_UNSIGNED_INT, value);
        } else {
            // Encode negative integer
            short positiveValue = (short) (-(short) (value + 1));
            encodeLength(MAJOR_TYPE_NEGATIVE_INT, positiveValue);
        }
    }

    /**
     * Encode a byte string
     *
     * @param data   Source data buffer
     * @param offset Offset in source buffer
     * @param length Length of data to encode
     */
    public void encodeByteString(byte[] data, short offset, short length) {
        encodeLength(MAJOR_TYPE_BYTE_STRING, length);

        // Copy data
        if ((short) (position + length) > bufferLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        Util.arrayCopy(data, offset, buffer, position, length);
        position += length;
    }

    /**
     * Encode a text string (UTF-8)
     *
     * @param text   Source text buffer (assumed UTF-8)
     * @param offset Offset in source buffer
     * @param length Length of text to encode
     */
    public void encodeTextString(byte[] text, short offset, short length) {
        encodeLength(MAJOR_TYPE_TEXT_STRING, length);

        // Copy text data
        if ((short) (position + length) > bufferLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        Util.arrayCopy(text, offset, buffer, position, length);
        position += length;
    }

    /**
     * Encode a boolean value
     *
     * @param value Boolean value to encode
     */
    public void encodeBoolean(boolean value) {
        checkBufferSpace((short) 1);

        if (value) {
            buffer[position++] = (byte) ((MAJOR_TYPE_FLOAT_SIMPLE << 5) | SIMPLE_TRUE);
        } else {
            buffer[position++] = (byte) ((MAJOR_TYPE_FLOAT_SIMPLE << 5) | SIMPLE_FALSE);
        }
    }

    /**
     * Encode a null value
     */
    public void encodeNull() {
        checkBufferSpace((short) 1);
        buffer[position++] = (byte) ((MAJOR_TYPE_FLOAT_SIMPLE << 5) | SIMPLE_NULL);
    }

    /**
     * Encode CBOR length with appropriate additional information
     *
     * @param majorType CBOR major type
     * @param length    Length or value to encode
     */
    private void encodeLength(byte majorType, short length) {
        if (length < 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        checkBufferSpace((short) 3); // Maximum 3 bytes needed

        if (length < 24) {
            // Direct encoding in additional information
            buffer[position++] = (byte) ((majorType << 5) | length);
        } else if (length < 256) {
            // 1 byte follows
            buffer[position++] = (byte) ((majorType << 5) | AI_UINT8_FOLLOWS);
            buffer[position++] = (byte) length;
        } else {
            // 2 bytes follow (16-bit length)
            buffer[position++] = (byte) ((majorType << 5) | AI_UINT16_FOLLOWS);
            buffer[position++] = (byte) (length >> 8);
            buffer[position++] = (byte) length;
        }
    }

    /**
     * Check if sufficient buffer space is available
     *
     * @param bytesNeeded Number of bytes needed
     */
    private void checkBufferSpace(short bytesNeeded) {
        if ((short) (position + bytesNeeded) > bufferLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
    }

    /**
     * Get current encoder position (number of bytes encoded)
     *
     * @return Current position in output buffer
     */
    public short getPosition() {
        return position;
    }

    /**
     * Get current buffer
     *
     * @return Current output buffer
     */
    public byte[] getBuffer() {
        return buffer;
    }

    /**
     * Get number of bytes encoded so far
     *
     * @return Number of bytes encoded since last init()
     */
    public short getEncodedLength() {
        return position; // Assumes init was called with offset 0
    }

    /**
     * Encode FIDO2 attestation object in packed format
     *
     * @param authData       Authenticator data
     * @param authDataLength Length of authenticator data
     * @param signature      Attestation signature
     * @param sigLength      Length of signature
     */
    public void encodePackedAttestationObject(byte[] authData, short authDataLength,
                                              byte[] signature, short sigLength) {
        // Encode map with 3 entries: fmt, authData, attStmt
        encodeMapStart((short) 3);

        // "fmt": "packed"
        encodeTextString(TXT_FMT, (short) 0, (short) 3);
        encodeTextString(TXT_PACKED, (short) 0, (short) 6);

        // "authData": <authenticator data>
        encodeTextString(TXT_AUTHDATA, (short) 0, (short) 8);
        encodeByteString(authData, (short) 0, authDataLength);

        // "attStmt": attestation statement
        encodeTextString(TXT_ATTSTMS, (short) 0, (short) 7);
        encodeMapStart((short) 2);

        // "alg": -7 (ES256)
        encodeTextString(TXT_ALG, (short) 0, (short) 3);
        encodeInteger((short) -7);

        // "sig": signature
        encodeTextString(TXT_SIG, (short) 0, (short) 3);
        encodeByteString(signature, (short) 0, sigLength);
    }

    /**
     * Encode FIDO2 attestation object in none format
     *
     * @param authData       Authenticator data
     * @param authDataLength Length of authenticator data
     */
    public void encodeNoneAttestationObject(byte[] authData, short authDataLength) {
        // Encode map with 2 entries: fmt, authData

        // Encode attestation object map with 2 entries: {fmt, authData}
        encodeMapStart((short) 2);

        // "fmt": "none"
        encodeTextString(TXT_FMT, (short) 0, (short) 3);
        encodeTextString(TXT_NONE, (short) 0, (short) 4);

        // "authData": <authenticator data>
        encodeTextString(TXT_AUTHDATA, (short) 0, (short) 8);
        encodeByteString(authData, (short) 0, authDataLength);
    }

    /**
     * Encode FIDO2 assertion response
     *
     * @param credentialId   Credential ID used for assertion
     * @param authData       Authenticator data
     * @param authDataLength Length of authenticator data
     * @param signature      Assertion signature
     * @param sigLength      Length of signature
     */
    public void encodeAssertionResponse(byte[] credentialId,
                                        byte[] authData, short authDataLength,
                                        byte[] signature, short sigLength) {
        // Encode map with 3 entries: credential, authData, signature
        encodeMapStart((short) 3);

        // Field 1: credential
        encodeInteger((short) 1);
        encodeMapStart((short) 2);

        // credential.type = "public-key"
        encodeTextString(TXT_TYPE, (short) 0, (short) 4);
        encodeTextString(TXT_PUBKEY, (short) 0, (short) 10);

        // credential.id = credentialId
        encodeTextString(TXT_ID, (short) 0, (short) 2);
        encodeByteString(credentialId, (short) 0, (short) 32);

        // Field 2: authData
        encodeInteger((short) 2);
        encodeByteString(authData, (short) 0, authDataLength);

        // Field 3: signature
        encodeInteger((short) 3);
        encodeByteString(signature, (short) 0, sigLength);
    }
}