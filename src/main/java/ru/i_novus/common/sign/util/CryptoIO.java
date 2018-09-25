package ru.i_novus.common.sign.util;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.spec.PKCS8EncodedKeySpec;

@Slf4j
public class CryptoIO {
    private CryptoIO () {
        // не позволяет создать экземпляр класса, класс утилитный
    }

    public static PKCS8EncodedKeySpec readPkFromFile(final String keyPath) throws IOException {
        byte[] data = Files.readAllBytes(Paths.get(keyPath));
        return new PKCS8EncodedKeySpec(data);
    }

    public static X509CertificateHolder readCertFromFile(final String crtPath) throws IOException {
        byte[] data = Files.readAllBytes(Paths.get(crtPath));
        return new X509CertificateHolder(data);
    }

    public static String writeCertToFile(final X509CertificateHolder certificateHolder, final Path path) throws IOException {
        if (path.toFile().exists()) {
            Files.delete(path);
        }
        try (OutputStream fos = Files.newOutputStream(path, StandardOpenOption.CREATE)) {
            fos.write(certificateHolder.getEncoded());
        }
        return path.toString();
    }

    public static String writePKToFile(final KeyPair keyPair, final Path path) throws IOException {
        if (path.toFile().exists()) {
            Files.delete(path);
        }
        try (OutputStream fos = Files.newOutputStream(path, StandardOpenOption.CREATE)) {
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
            fos.write(pkcs8EncodedKeySpec.getEncoded());
        }
        return path.toString();
    }
}
