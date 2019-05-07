package ru.i_novus.common.sign.api;

/*-
 * -----------------------------------------------------------------
 * common-sign-gost-api
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

/**
 * Идентификаторы ГОСТ-алгоритмов
 */
public final class GostIds {

    public static final String GOST3411_URI = "http://www.w3.org/2001/04/xmldsig-more#gostr3411";
    public static final String GOST3411_URN = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr3411";
    public static final String GOST3410_2001_URI = "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411";
    public static final String GOST3410_2001_URN = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102001-gostr3411";

    public static final String GOST3411_2012_256_URI = "http://www.w3.org/2001/04/xmldsig-more#gostr34112012-256";
    public static final String GOST3411_2012_256_URN = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256";
    public static final String GOST3410_2012_256_URI = "http://www.w3.org/2001/04/xmldsig-more#gostr34102012-gostr34112012-256";
    public static final String GOST3410_2012_256_URN = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256";

    public static final String GOST3411_2012_512_URI = "http://www.w3.org/2001/04/xmldsig-more#gostr34112012-512";
    public static final String GOST3411_2012_512_URN = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-512";
    public static final String GOST3410_2012_512_URI = "http://www.w3.org/2001/04/xmldsig-more#gostr34102012-gostr34112012-512";
    public static final String GOST3410_2012_512_URN = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512";

    private GostIds() {
        // не позволяет создать экземпляр класса, класс утилитный
    }
}
