package ru.i_novus.common.sign.util;

import org.apache.xpath.XPathAPI;
import org.w3c.dom.Node;
import ru.i_novus.common.sign.exception.CommonSignRuntimeException;

import javax.xml.namespace.NamespaceContext;
import javax.xml.transform.TransformerException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

public class XPathUtil {

    private XPathUtil() {
        throw new InstantiationError("Must not instantiate this class");
    }

    public static Node selectSingleNode(Node contextNode, String str) throws CommonSignRuntimeException {
        try {
            return XPathAPI.selectSingleNode(contextNode, str, contextNode);
        } catch (TransformerException e) {
            throw new CommonSignRuntimeException(e);
        }
    }

    public static Node evaluate(String expression, Node itemNode, NamespaceContext nsContext){

        XPath xpath = XPathFactory.newInstance().newXPath();

        if(nsContext != null){
            xpath.setNamespaceContext(nsContext);
        }

        try {
            return (Node) xpath.evaluate(expression, itemNode, XPathConstants.NODE);
        } catch (XPathExpressionException e) {
            throw new CommonSignRuntimeException(e);
        }
    }

    public static String evaluateString(String expression, Node itemNode, NamespaceContext nsContext){

        XPath xpath = XPathFactory.newInstance().newXPath();

        if(nsContext != null){
            xpath.setNamespaceContext(nsContext);
        }

        try {
            return (String) xpath.evaluate(expression, itemNode, XPathConstants.STRING);
        } catch (XPathExpressionException e) {
            throw new CommonSignRuntimeException(e);
        }
    }
}
