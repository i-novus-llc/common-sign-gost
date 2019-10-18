package ru.i_novus.common.sign.service.core.impl;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import ru.i_novus.common.sign.service.core.api.KeystoreService;
import ru.i_novus.common.sign.service.core.config.SignServiceConfig;
import ru.i_novus.common.sign.util.CryptoIO;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.nio.file.Files.list;

@Slf4j
public class FileKeystoreServiceImpl implements KeystoreService {

    private static Map<BigInteger, Path> storage = new HashMap<>();

    @Autowired
    private SignServiceConfig signServiceConfig;

    @Autowired
    private CryptoIO cryptoIO;

    @Autowired
    private ResourceLoader resourceLoader;

    private FileKeystoreServiceImpl self;

    @Autowired
    public void setSelf(FileKeystoreServiceImpl self) {
        this.self = self;
    }

    @PostConstruct
    public void init() {
        if (!"file".equals(signServiceConfig.getStorage().getType())) {
            return;
        }

        Resource resource = resourceLoader.getResource(signServiceConfig.getStorage().getPath());

        Path path;
        try {
            path = resource.getFile().toPath();
            KeystorageWatchService watchService = new KeystorageWatchService(path, self);
            Thread thread = new Thread(watchService);
            thread.start();

            initKeyStorage(path);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot init key storage", e);
        }
    }

    private void initKeyStorage(Path path) throws IOException {
        if (!path.toFile().exists()) {
            Files.createDirectories(path);
        }

        try (Stream<Path> pathStream = list(path)) {
            for (Path file : pathStream.filter(p -> p.toFile().isFile()).map(Path::toAbsolutePath).collect(Collectors.toList())) {
                try {
                    addKey(file);
                } catch (RuntimeException e) {
                    logger.warn("Cannot add key '{}'", file, e);
                }
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

    public void addKey(Path path) {
        String password = getKeystorePassword(path.getFileName().toString()).orElse("");
        X509Certificate certificate = cryptoIO.readCertificateFromPKCS12(path, password);
        storage.put(certificate.getSerialNumber(), path);
    }

    public void modifyKey(Path path) {
        addKey(path);
    }

    public void removeKey(Path path) {
        Set<BigInteger> serialNumbers = new HashSet<>();
        Path absolutePath = path.toAbsolutePath();

        for (Map.Entry<BigInteger, Path> storageEntry : storage.entrySet()) {
            if ((absolutePath.toFile().isFile() && storageEntry.getValue().equals(absolutePath)) ||
                    (absolutePath.toFile().isDirectory() && storageEntry.getValue().startsWith(absolutePath)))
                serialNumbers.add(storageEntry.getKey());
        }
        if (!serialNumbers.isEmpty())
            serialNumbers.forEach(storage::remove);
    }

    public Map<BigInteger, Path> getStorage() {
        return new HashMap<>(storage);
    }
}
