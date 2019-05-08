package ru.i_novus.common.sign.smev3;

import org.apache.xml.security.transforms.TransformationException;
import org.w3c.dom.Element;
import ru.i_novus.common.sign.util.DomUtil;

import javax.xml.transform.TransformerException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Smev3Util {
    private Smev3Util() {
        // не позволяет создать экземпляр класса, класс утилитный
    }

    /**
     * Возвращает массив байтов трансформированного XML-элемента, в соответствии с требованиями методических рекомендаций 3.*
     *
     * @param untransformedElement объект элемента для обработки
     * @return строкое представление XML элемента, преобразованного в соответствии с требованиями методических рекомендаций 3.*
     * @return
     * @throws IOException
     * @throws TransformationException
     * @throws TransformerException
     */
    static byte[] getTransformedXml(Element untransformedElement) throws IOException, TransformationException, TransformerException {

        SmevTransformSpi transform = new SmevTransformSpi();

        final String untransformedXml = DomUtil.elementToString(untransformedElement, StandardCharsets.UTF_8);

        byte[] untransformedElementBytes = untransformedXml.getBytes(UTF_8);

        byte[] resultBytes;

        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            try (InputStream inputStream = new ByteArrayInputStream(untransformedElementBytes)) {

                transform.process(inputStream, out);

                resultBytes = out.toByteArray();
            }
        }

        return resultBytes;
    }
}
