package ru.rt.eu.arm.common.sign.util;

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