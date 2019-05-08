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
package ru.i_novus.common.sign.util;

import lombok.extern.slf4j.Slf4j;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.nio.charset.Charset;

@Slf4j
public class DomUtil {

    private DomUtil() {
        // не позволяет создать экземпляр класса, класс утилитный
    }

    public static Document newDocument() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        return dbf.newDocumentBuilder().newDocument();
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

    /**
     * Возвращает строку преобразованная из объекта класса org.w3c.dom.Element
     *
     * @param element     объект элемента для обработки
     * @param xmlEncoding кодировка, которая задаётся в объявлении XML
     * @return строкое представление XML элемента
     * @throws TransformerConfigurationException
     */
    public static String elementToString(final Element element, final Charset xmlEncoding) throws TransformerException {

        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

        Transformer tf = factory.newTransformer();
        tf.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        tf.setOutputProperty(OutputKeys.INDENT, "yes");
        tf.setOutputProperty(OutputKeys.ENCODING, xmlEncoding.name());

        StringWriter writer = new StringWriter();

        tf.transform(new DOMSource(element), new StreamResult(writer));

        return writer.toString();
    }
}
