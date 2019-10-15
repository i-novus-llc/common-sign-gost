package ru.i_novus.common.sign.service.core.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import ru.i_novus.common.sign.service.core.api.KeystoreService;
import ru.i_novus.common.sign.service.core.impl.FileKeystoreServiceImpl;

@Configuration
public class ServiceConfig {

    @Autowired
    private SignServiceConfig signServiceConfig;

    @Bean
    public KeystoreService keystoreService() {
        final String storageType = signServiceConfig.getStorage().getType();

        KeystoreService keystoreService;
        if ("file".equals(storageType)) {
            keystoreService = new FileKeystoreServiceImpl();
        } else {
            throw new IllegalArgumentException("Unsupported storage type: " + storageType);
        }
        return keystoreService;
    }
}
