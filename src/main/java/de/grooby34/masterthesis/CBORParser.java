package de.grooby34.masterthesis;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * CBOR Parser for JavaCard FIDO2 Implementation
 *
 * <p>Lightweight CBOR parser specifically designed for CTAP2 protocol parsing on JavaCard platforms
 * with memory constraints.
 *
 * <p>Features: - FIDO2-specific field extraction methods - Memory-efficient parsing without dynamic
 * allocation - Support for all CBOR major types used in CTAP2 - Robust error handling for malformed
 * data
 *
 * @author Tobias Franke
 * @version 1.0
 */
public class CBORParser {

  // CBOR Major Types
  private static final byte MAJOR_TYPE_UNSIGNED_INT = 0x00;
  private static final byte MAJOR_TYPE_NEGATIVE_INT = 0x01;
  private static final byte MAJOR_TYPE_BYTE_STRING = 0x02;
  private static final byte MAJOR_TYPE_TEXT_STRING = 0x03;
  private static final byte MAJOR_TYPE_ARRAY = 0x04;
  private static final byte MAJOR_TYPE_MAP = 0x05;
  private static final byte MAJOR_TYPE_TAG = 0x06;
  private static final byte MAJOR_TYPE_FLOAT_SIMPLE = 0x07;

  // CBOR Additional Information
  private static final byte AI_UINT8_FOLLOWS = 0x18; // 24
  private static final byte AI_UINT16_FOLLOWS = 0x19; // 25
  private static final byte AI_UINT32_FOLLOWS = 0x1A; // 26
  private static final byte AI_UINT64_FOLLOWS = 0x1B; // 27

  // Parser state
  private byte[] data;
  private short position;
  private short dataLength;

  // Cache for last parsed values
  private short lastMapLength;
  private short lastArrayLength;
  private short lastIntegerValue;

  /** Default constructor */
  public CBORParser() {
    this.data = new byte[256];
    this.position = 0;
    this.dataLength = 0;
  }

  /**
   * Initialize parser with data buffer
   *
   * @param buffer Data buffer containing CBOR data
   * @param offset Start offset in buffer
   * @param length Length of CBOR data
   */
  public void init(byte[] buffer, short offset, short length) {
    Util.arrayCopy(buffer, (short) 0, data, (short) 0, (short) (length + offset));
    this.position = offset;
    this.dataLength = (short) (offset + length);
  }

  /**
   * Expect and parse a CBOR map start
   *
   * @return true if map start was found, false otherwise
   */
  public boolean expectMapStart() {
    if (position >= dataLength) {
      return false;
    }

    byte header = data[position++];
    byte majorType = (byte) ((header & 0xE0) >> 5);
    byte additionalInfo = (byte) (header & 0x1F);

    if (majorType != MAJOR_TYPE_MAP) {
      position--; // Restore position
      return false;
    }

    lastMapLength = parseLength(additionalInfo);
    return true;
  }

  /**
   * Expect and parse a CBOR array start
   *
   * @return true if array start was found, false otherwise
   */
  public boolean expectArrayStart() {
    if (position >= dataLength) {
      return false;
    }

    byte header = data[position++];
    byte majorType = (byte) ((header & 0xE0) >> 5);
    byte additionalInfo = (byte) (header & 0x1F);

    if (majorType != MAJOR_TYPE_ARRAY) {
      position--; // Restore position
      return false;
    }

    lastArrayLength = parseLength(additionalInfo);
    return true;
  }

  /**
   * Parse an integer key from current position
   *
   * @return Parsed integer value
   */
  public short parseIntegerKey() {
    return parseInteger();
  }

  /**
   * Parse a text string key from current position
   *
   * @param output Buffer to store the key
   * @param outputOffset Offset in output buffer
   * @param maxLength Maximum length to parse
   * @return Length of parsed key
   */
  public short parseTextStringKey(byte[] output, short outputOffset, short maxLength) {
    return parseTextString(output, outputOffset, maxLength);
  }

  /**
   * Parse an integer value from current position
   *
   * @return Parsed integer value
   */
  public short parseInteger() {
    if (position >= dataLength) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    byte header = data[position++];
    byte majorType = (byte) ((header & 0xE0) >> 5);
    byte additionalInfo = (byte) (header & 0x1F);

    if (majorType == MAJOR_TYPE_UNSIGNED_INT) {
      short value = parseLength(additionalInfo);
      lastIntegerValue = value;
      return value;
    } else if (majorType == MAJOR_TYPE_NEGATIVE_INT) {
      short value = (short) -(short) (parseLength(additionalInfo) + 1);
      lastIntegerValue = value;
      return value;
    } else {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      return 0;
    }
  }

  /**
   * Parse a byte string from current position
   *
   * @param output Buffer to store parsed bytes
   * @param outputOffset Offset in output buffer
   * @param maxLength Maximum number of bytes to parse
   * @return Number of bytes actually parsed
   */
  public short parseByteString(byte[] output, short outputOffset, short maxLength) {
    if (position >= dataLength) {
      return 0;
    }

    byte header = data[position++];
    byte majorType = (byte) ((header & 0xE0) >> 5);
    byte additionalInfo = (byte) (header & 0x1F);

    if (majorType != MAJOR_TYPE_BYTE_STRING) {
      position--; // Restore position
      return 0;
    }

    short length = parseLength(additionalInfo);
    if (length > maxLength) {
      length = maxLength;
    }

    if ((short) (position + length) > dataLength) {
      return 0;
    }

    Util.arrayCopy(data, position, output, outputOffset, length);
    position += length;

    return length;
  }

  /**
   * Parse a text string from current position
   *
   * @param output Buffer to store parsed string
   * @param outputOffset Offset in output buffer
   * @param maxLength Maximum length to parse
   * @return Length of parsed string
   */
  public short parseTextString(byte[] output, short outputOffset, short maxLength) {
    if (position >= dataLength) {
      return 0;
    }

    byte header = data[position++];
    byte majorType = (byte) ((header & 0xE0) >> 5);
    byte additionalInfo = (byte) (header & 0x1F);

    if (majorType != MAJOR_TYPE_TEXT_STRING) {
      position--; // Restore position
      return 0;
    }

    short length = parseLength(additionalInfo);
    if (length > maxLength) {
      length = maxLength;
    }

    if ((short) (position + length) > dataLength) {
      return 0;
    }

    Util.arrayCopy(data, position, output, outputOffset, length);
    position += length;

    return length;
  }

  /** Skip the current CBOR value without parsing it */
  public void skipValue() {
    if (position >= dataLength) {
      return;
    }

    byte header = data[position++];
    byte majorType = (byte) ((header & 0xE0) >> 5);
    byte additionalInfo = (byte) (header & 0x1F);

    switch (majorType) {
      case MAJOR_TYPE_UNSIGNED_INT:
      case MAJOR_TYPE_NEGATIVE_INT:
        skipLength(additionalInfo);
        break;

      case MAJOR_TYPE_BYTE_STRING:
      case MAJOR_TYPE_TEXT_STRING:
        short length = parseLength(additionalInfo);
        position += length;
        break;

      case MAJOR_TYPE_ARRAY:
        short arrayLength = parseLength(additionalInfo);
        for (short i = 0; i < arrayLength; i++) {
          skipValue(); // Recursively skip array elements
        }
        break;

      case MAJOR_TYPE_MAP:
        short mapLength = parseLength(additionalInfo);
        for (short i = 0; i < mapLength; i++) {
          skipValue(); // Skip key
          skipValue(); // Skip value
        }
        break;

      case MAJOR_TYPE_TAG:
        skipLength(additionalInfo);
        skipValue(); // Skip tagged value
        break;

      case MAJOR_TYPE_FLOAT_SIMPLE:
        if (additionalInfo < 24) {
          // Simple value, no additional bytes
        } else if (additionalInfo == 24) {
          position++; // Skip 1 byte
        } else if (additionalInfo == 25) {
          position += 2; // Skip 2 bytes
        } else if (additionalInfo == 26) {
          position += 4; // Skip 4 bytes
        } else if (additionalInfo == 27) {
          position += 8; // Skip 8 bytes
        }
        break;
    }
  }

  /**
   * Parse length field from additional information
   *
   * @param additionalInfo Additional information from CBOR header
   * @return Parsed length value
   */
  private short parseLength(byte additionalInfo) {
    if (additionalInfo < 24) {
      return (short) (additionalInfo & 0x1F);
    } else if (additionalInfo == AI_UINT8_FOLLOWS) {
      if (position >= dataLength) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      return (short) (data[position++] & 0xFF);
    } else if (additionalInfo == AI_UINT16_FOLLOWS) {
      if ((short) (position + 1) >= dataLength) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      short value =
          (short) (((data[position] & 0xFF) << 8) | (data[(short) (position + 1)] & 0xFF));
      position += 2;
      return value;
    } else if (additionalInfo == AI_UINT32_FOLLOWS) {
      if ((short) (position + 3) >= dataLength) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      // For JavaCard, we only support 16-bit lengths
      position += 2; // Skip high 16 bits
      short value =
          (short) (((data[position] & 0xFF) << 8) | (data[(short) (position + 1)] & 0xFF));
      position += 2;
      return value;
    } else {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      return 0;
    }
  }

  /**
   * Skip length bytes based on additional information
   *
   * @param additionalInfo Additional information from CBOR header
   */
  private void skipLength(byte additionalInfo) {
    if (additionalInfo < 24) {
      // No additional bytes
    } else if (additionalInfo == AI_UINT8_FOLLOWS) {
      position++;
    } else if (additionalInfo == AI_UINT16_FOLLOWS) {
      position += 2;
    } else if (additionalInfo == AI_UINT32_FOLLOWS) {
      position += 4;
    } else if (additionalInfo == AI_UINT64_FOLLOWS) {
      position += 8;
    }
  }

  /**
   * Get the length of the last parsed map
   *
   * @return Map length
   */
  public short getLastMapLength() {
    return lastMapLength;
  }

  /**
   * Get the length of the last parsed array
   *
   * @return Array length
   */
  public short getLastArrayLength() {
    return lastArrayLength;
  }
}
