package ru.i_novus.common.sign.util;

/*-
 * -----------------------------------------------------------------
 * common-sign-gost
 * -----------------------------------------------------------------
 * Copyright (C) 2018 - 2019 I-Novus LLC
 * -----------------------------------------------------------------
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
 * -----------------------------------------------------------------
 */

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
