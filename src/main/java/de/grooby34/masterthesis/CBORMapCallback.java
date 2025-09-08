package de.grooby34.masterthesis;

/**
 * Callback interface for map parsing
 */
public interface CBORMapCallback {
    void onIntegerKey(short key);
    void onTextKey(byte[] key, short offset, short length);
    void onValue(CBORParser parser);
}
