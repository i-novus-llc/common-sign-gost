package ru.i_novus.common.sign.util;

import java.util.Base64;

public class Base64Util {
    private Base64Util() {
        // don't instantiate
    }

    /**
     * Get data in byte array format from Base64 byte array format
     *
     * @param data Base64 byte array representation of data
     * @return data in byte array format
     */
    public static byte[] getBase64Decoded(byte[] data) {
        return Base64.getDecoder().decode(data);
    }

    /**
     * Get data in byte array format from Base64 string format
     *
     * @param data Base64 String representation
     * @return data in byte array format
     */
    public static byte[] getBase64Decoded(String data) {
        return getBase64Decoded(data.getBytes());
    }

    /**
     * Get Base64 byte array for data in byte array format
     *
     * @param data input data
     * @return Base64 encoded data in byte array representation
     */
    public static byte[] getBase64Encoded(byte[] data) {
        return Base64.getEncoder().encode(data);
    }

    /**
     * Get Base64 string for data in byte array format
     *
     * @param data input data
     * @return Base64 String representation
     */
    public static String getBase64EncodedString(byte[] data) {
        return new String(getBase64Encoded(data));
    }
}
