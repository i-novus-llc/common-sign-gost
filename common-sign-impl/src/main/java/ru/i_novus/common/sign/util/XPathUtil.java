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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;
import javax.xml.namespace.NamespaceContext;
import javax.xml.xpath.*;

public class XPathUtil {
    private static final Logger logger = LoggerFactory.getLogger(XPathUtil.class);

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
