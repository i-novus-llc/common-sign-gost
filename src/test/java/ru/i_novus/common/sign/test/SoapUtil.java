package ru.i_novus.common.sign.test;

import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

final class SoapUtil {
    SoapUtil() {
        // don't create class instance
    }

    static SOAPMessage constructMessage(InputStream xmlData, String protocol) {
        SOAPMessage message;
        try {
            MessageFactory mFactory = MessageFactory.newInstance(protocol);
            message = mFactory.createMessage(null, xmlData);
        } catch (SOAPException | IOException e) {
            throw new RuntimeException(e);
        }
        return message;
    }

    static String getSoapMessageContent(SOAPMessage message) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            message.writeTo(outputStream);
        } catch (SOAPException | IOException e) {
            throw new RuntimeException(e);
        }
        return outputStream.toString().replace("&#13;", "");
    }
}
