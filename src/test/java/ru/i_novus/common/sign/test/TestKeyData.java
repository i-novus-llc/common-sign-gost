package ru.i_novus.common.sign.test;

import lombok.Getter;
import ru.i_novus.common.sign.util.CryptoFormatConverter;
import ru.i_novus.common.sign.util.SignAlgorithmType;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

@Getter
enum TestKeyData {
    GOST_2001(
            "MIGRAgEAMBEGBiqFAwICEwYHKoUDAgIjAQR5MHcCAQEEIHeMLlO27p0BPaXNeeqINusNWJI98yQ2tHTkMI/B94ARoAkGByqFAwICIwGhRQNDAARA7BZcxtG9fcAFJ0sPrFh31G0yZndTUegvNZeZCOjoytikcxiIcRKLkF5sO32vqG/zr1oOlsAUE//a/tWABSv+Qw==",
            "MIICAzCCAbACCQCRwSrCqVBfCjAKBgYqhQMCAgMFADCBhzELMAkGA1UEBhMCUlUxDzANBgNVBAgMBk1vc2NvdzEPMA0GA1UEBwwGTW9zY293MQwwCgYDVQQKDANOQ0kxDjAMBgNVBAsMBUVHSVNaMRUwEwYDVQQDDAxhcm0ucnQtZXUucnUxITAfBgkqhkiG9w0BCQEWEmVnaXN6LWFkbUBydC1ldS5ydTAeFw0xODA0MDYwNzQ2MDhaFw0yODA0MDMwNzQ2MDhaMIGHMQswCQYDVQQGEwJSVTEPMA0GA1UECAwGTW9zY293MQ8wDQYDVQQHDAZNb3Njb3cxDDAKBgNVBAoMA05DSTEOMAwGA1UECwwFRUdJU1oxFTATBgNVBAMMDGFybS5ydC1ldS5ydTEhMB8GCSqGSIb3DQEJARYSZWdpc3otYWRtQHJ0LWV1LnJ1MGMwHAYGKoUDAgITMBIGByqFAwICIwEGByqFAwICHgEDQwAEQMa3B6lusXw8/5FaydYwfHoqtlKy3eNFUj2FBVhZqOYcmNMbaAgtLyYiLSkZcJcqdOgoMur4qDRIdLZwjxhV/rwwCgYGKoUDAgIDBQADQQB11MpwTus8zGCyAWauJsKFW+83AVEf/hyAertg2BByzwvlK0ju6QCT0xiZQ+OyEE3k4YIhGzXcsv22l9l31FHI"),
    GOST_2012_256("MEoCAQAwIQYIKoUDBwEBAQEwFQYJKoUDBwECAQEBBggqhQMHAQECAgQiBCAioTbWLT87W9Lo+3DbZVGENgHEVMQNyKVkQAUbFyKtBg==", "MIIDijCCAzGgAwIBAgIBATAKBggqhQMHAQEDAjCBwzEuMCwGA1UEAwwl0KTQndCh0JguINCi0LXRgdGC0L7QstCw0Y8g0YHRgNC10LTQsDFFMEMGA1UECgw80JzQuNC90LjRgdGC0LXRgNGB0YLQstC+INC30LTRgNCw0LLQvtC+0YXRgNCw0L3QtdC90LjRjyDQoNCkMSYwJAYJKoZIhvcNAQkBFhdub3JlcGx5Lm5yLnJ0QGdtYWlsLmNvbTEVMBMGA1UEBwwM0JzQvtGB0LrQstCwMQswCQYDVQQGEwJSVTAeFw0xODEwMTAwNzA2NTlaFw0xOTEwMTAwNzA2NTlaMIHDMS4wLAYDVQQDDCXQpNCd0KHQmC4g0KLQtdGB0YLQvtCy0LDRjyDRgdGA0LXQtNCwMUUwQwYDVQQKDDzQnNC40L3QuNGB0YLQtdGA0YHRgtCy0L4g0LfQtNGA0LDQstC+0L7RhdGA0LDQvdC10L3QuNGPINCg0KQxJjAkBgkqhkiG9w0BCQEWF25vcmVwbHkubnIucnRAZ21haWwuY29tMRUwEwYDVQQHDAzQnNC+0YHQutCy0LAxCzAJBgNVBAYTAlJVMIIBMjCB6wYHKoZIzj0CATCB3wIBATAsBgcqhkjOPQEBAiEA/////////////////////////////////////////ZcwRAQgwhc/FROYFnOvSJLCMDWifOJeIBO/laozsixlbyd+czUEIClfm650KO2czCDnw1mp1Boi/M2RCOF797qTN6b4rpUTBEEEkeOEQ6XoLA2ICSNCVxKyu2WLkZaTLgLHiyWC/nQtqigyh5QjqxoDdYlXhsS7RulWX94LU0R2Z0CvJorbMjIuXAIgQAAAAAAAAAAAAAAAAAAAAA/Yzd/Ie2Y1wRWvVWw2DGcCAQEDQgAEPwZj+QRttgsqsUdb6g94pKmtd+jgMQk58KeMa5pwfEP0YoweIXhhA5/9OtwGcznaKU4jVIn72VezaH7quQizkqM5MDcwDwYDVR0PAQH/BAUDAwf7gDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMAoGCCqFAwcBAQMCA0cAMEQCIDe092y+ap9Z1IQFtiMeHx52Cbr1brSC7ItdIhmWfIQ2AiAwswWZddJd5vFA1aBgpMlwUj0D0RTu2s2OVrVnHqrQMw=="),
    GOST_2012_512("MGoCAQAwIQYIKoUDBwEBAQIwFQYJKoUDBwECAQIBBggqhQMHAQECAwRCBECoVstjF3ZXciTXS52MZCGjrt2glbsv5wH2cOEuFQtv2czWsDSvd0p8KNGkLwEMsPNBHXI9sj5pjOy3unsgURoU", "MIGqMCEGCCqFAwcBAQECMBUGCSqFAwcBAgECAQYIKoUDBwEBAgMDgYQABIGAlUQ7l6gwDy8Kn0xqqkpS/eSNWeHW0OPf8bwbFpAoYdvA7K5xDZV88tsVyaQTcpyJmP2VSPO5LcB1cdY8nC3r+wqtq8j/vjCRsqSM5BgIRTDw10uIqkwVVOeisLEEbhO0s0YO+btJzzZmrlXlwRcfVmrFtxgfLV/4ekd4P9KblBc=");

    private static final CryptoFormatConverter converter = CryptoFormatConverter.getInstance();
    private String key;
    private String certificate;

    TestKeyData(String key, String certificate) {
        this.key = key;
        this.certificate = certificate;
    }

    public X509Certificate getX509Certificate() {
        return converter.getCertificateFromPEMEncoded(getCertificate());
    }

    public PrivateKey getPrivateKey() {
        X509Certificate certificate = getX509Certificate();
        SignAlgorithmType algorithmType = SignAlgorithmType.findByCertificate(certificate);
        return converter.getPKFromPEMEncoded(algorithmType, getKey());
    }
}
