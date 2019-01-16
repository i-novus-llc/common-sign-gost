package ru.i_novus.common.sign.util;

import org.apache.xml.security.transforms.TransformationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import ru.i_novus.common.sign.exception.CommonSignRuntimeException;
import ru.i_novus.common.sign.smev.SmevTransformSpi;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;

public class DomUtil {

    private DomUtil() {
        throw new InstantiationError("Must not instantiate this class");
    }

    public static DocumentBuilder newDocumentBuilder() {

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

        try {
            return dbf.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new CommonSignRuntimeException("SMEV3 Signer Integration.", e);
        }
    }

    public static Document newDocument() {
        return newDocumentBuilder().newDocument();
    }

    /**
     * Возвращает найденный первый дочерний элемент заданного узла
     *
     * @param node объект класса org.w3c.dom.Node
     * @return
     */
    public static Node getNodeFirstChild(final Node node) {

        NodeList nodes = node.getChildNodes();

        Node rootNode = null;

        for (int i = 0; i < nodes.getLength(); i++) {
            if (nodes.item(i).getNodeType() == Node.ELEMENT_NODE) {
                rootNode = nodes.item(i);
                break;
            }
        }

        return rootNode;
    }

    public static byte[] nodeToByte(Node contextNode) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            org.apache.xml.security.utils.XMLUtils.outputDOM(contextNode, baos, false);
            return baos.toByteArray();
        } catch (IOException e) {
            throw new CommonSignRuntimeException(e);
        }
    }

    /**
     * Возвращает массив байтов трансформированного XML-элемента, в соответствии с требованиями методических рекомендаций 3.*
     *
     * @param untransformedElement объект элемента для обработки
     * @return строкое представление XML элемента, преобразованного в соответствии с требованиями методических рекомендаций 3.*
     */
    public static byte[] getTransformedXml(Element untransformedElement) {

        SmevTransformSpi transform = new SmevTransformSpi();

        byte[] untransformedElementBytes = nodeToByte(untransformedElement);

        byte[] resultBytes;

        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            try (InputStream inputStream = new ByteArrayInputStream(untransformedElementBytes)) {

                transform.process(inputStream, out);

                resultBytes = out.toByteArray();

            } catch (TransformationException e) {
                throw new CommonSignRuntimeException("Не удалось преобразовать объект класса org.w3c.dom.Element в строку, в соответствии с требованиями методических рекомендаций 3.*", e);
            }
        } catch (IOException e) {
            throw new CommonSignRuntimeException("Cannot process transformed xml", e);
        }

        return resultBytes;
    }
}
