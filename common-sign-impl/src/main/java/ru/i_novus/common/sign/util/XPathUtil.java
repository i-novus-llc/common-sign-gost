package ru.i_novus.common.sign.util;

import lombok.extern.slf4j.Slf4j;
import org.w3c.dom.Node;
import javax.xml.namespace.NamespaceContext;
import javax.xml.xpath.*;

@Slf4j
public class XPathUtil {

    private XPathUtil() {
        // не позволяет создать экземпляр класса, класс утилитный
    }

    public static Node evaluate(String expression, Node itemNode, NamespaceContext nsContext) throws XPathExpressionException {

        XPath xpath = XPathFactory.newInstance().newXPath();

        if(nsContext != null){
            xpath.setNamespaceContext(nsContext);
        }

        return (Node) xpath.evaluate(expression, itemNode, XPathConstants.NODE);
    }

    public static String evaluateString(String expression, Node itemNode, NamespaceContext nsContext) throws XPathExpressionException {

        XPath xpath = XPathFactory.newInstance().newXPath();

        if(nsContext != null){
            xpath.setNamespaceContext(nsContext);
        }

        return (String) xpath.evaluate(expression, itemNode, XPathConstants.STRING);
    }
}
