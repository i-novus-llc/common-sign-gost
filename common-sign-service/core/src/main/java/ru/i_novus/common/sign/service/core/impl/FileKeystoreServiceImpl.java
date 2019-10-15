package ru.i_novus.common.sign.service.core.impl;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import ru.i_novus.common.sign.service.core.api.KeystoreService;
import ru.i_novus.common.sign.service.core.config.SignServiceConfig;
import ru.i_novus.common.sign.util.CryptoIO;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
public class FileKeystoreServiceImpl implements KeystoreService {

    private static Map<BigInteger, Path> storage = new HashMap<>();

    @Autowired
    private SignServiceConfig signServiceConfig;

    @Autowired
    private CryptoIO cryptoIO;

    @Autowired
    private ResourceLoader resourceLoader;

    @PostConstruct
    public void init() {
        //todo use WatchService
//        DefaultResourceLoader resourceLoader = new DefaultResourceLoader();
        Resource resource = resourceLoader.getResource(signServiceConfig.getStorage().getPath());

        try {
            initKeyStorage(resource.getFile().getPath());
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot init key storage", e);
        }
    }

    private void initKeyStorage(String storagePath) throws IOException {

        Path path = Paths.get(storagePath);
        if (!path.toFile().exists()) {
            Files.createDirectories(path);
        }

        try (Stream<Path> pathStream = Files.list(path)) {
            for (Path file : pathStream.filter(p -> p.toFile().isFile()).collect(Collectors.toList())) {
                String password = getKeystorePassword(file.getFileName().toString()).orElse("");
                X509Certificate certificate = cryptoIO.readCertificateFromPKCS12(file, password);
                storage.put(certificate.getSerialNumber(), file);
            }
        }
    }

    private Optional<String> getKeystorePassword(String keystoreName) {
        return Optional.ofNullable(signServiceConfig.getStorage().getPasswords().get(keystoreName));
    }

    @Override
    public Optional<PrivateKey> getPrivateKey(BigInteger certificateSerialNumber) {
        Path file = storage.get(certificateSerialNumber);
        if (file == null || !file.toFile().exists())
            return Optional.empty();

        Optional<PrivateKey> result;

        try {
            String keystoreName = file.getFileName().toString();
            try (InputStream fileInputStream = Files.newInputStream(file)) {
                result = Optional.of(cryptoIO.readPrivateKeyFromPKCS12(fileInputStream,
                        getKeystorePassword(keystoreName).orElseThrow(
                                () -> new IllegalStateException("Cannot find password for file '" + keystoreName + "'")
                        )));
            }
            return result;
        } catch (IOException e) {
            logger.error("Cannot open file '{}' as keystore in PKCS12", file, e);
            return Optional.empty();
        }
    }

    @Override
    public Optional<X509Certificate> getCertificate(BigInteger serialNumber) {
        Path file = storage.get(serialNumber);
        if (file == null || !file.toFile().exists())
            return Optional.empty();

        Optional<X509Certificate> result;

        try {
            String keystoreName = file.getFileName().toString();
            try (InputStream fileInputStream = Files.newInputStream(file)) {
                result = Optional.of(cryptoIO.readCertificateFromPKCS12(fileInputStream,
                        getKeystorePassword(keystoreName).orElseThrow(
                                () -> new IllegalStateException("Cannot find password for file '" + keystoreName + "'")
                        )));
            }
            return result;
        } catch (IOException e) {
            logger.error("Cannot open file '{}' as keystore in PKCS12", file, e);
            return Optional.empty();
        }
    }
}
