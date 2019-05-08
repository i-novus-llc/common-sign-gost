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

package ru.i_novus.common.sign.soap;

import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public final class SoapUtil {
    private SoapUtil() {
        // don't create class instance
    }

    public static SOAPMessage constructMessage(InputStream xmlData, String protocol) {
        SOAPMessage message;
        try {
            MessageFactory mFactory = MessageFactory.newInstance(protocol);
            message = mFactory.createMessage(null, xmlData);
        } catch (SOAPException | IOException e) {
            throw new RuntimeException(e);
        }
        return message;
    }

    public static String getSoapMessageContent(SOAPMessage message) {
        String content;
        try(ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            message.writeTo(outputStream);
            content = outputStream.toString().replace("&#13;", "");
        } catch (SOAPException | IOException e) {
            throw new RuntimeException(e);
        }
        return content;
    }
}
