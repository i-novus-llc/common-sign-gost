package ru.i_novus.common.sign.util;

import lombok.extern.slf4j.Slf4j;

import javax.activation.DataHandler;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

@Slf4j
public class StreamUtil {

    private StreamUtil() {
        // не позволяет создать экземпляр класса, класс утилитный
    }

    public static byte[] dataHandlerToByteArray(final DataHandler content) throws IOException {

        int byteCount = 0;

        byte[] buffer = new byte[4096];

        int bytesRead1;

        try (InputStream in = content.getInputStream();
             ByteArrayOutputStream out = new ByteArrayOutputStream(4096)) {

            for (boolean bytesRead = true; (bytesRead1 = in.read(buffer)) != -1; byteCount += bytesRead1) {
                out.write(buffer, 0, bytesRead1);
            }

            out.flush();

            return out.toByteArray();
        }
    }
}
