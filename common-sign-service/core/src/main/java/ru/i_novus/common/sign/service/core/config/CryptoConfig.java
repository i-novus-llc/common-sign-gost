package ru.i_novus.common.sign.service.core.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import ru.i_novus.common.sign.Init;
import ru.i_novus.common.sign.util.CryptoIO;

import javax.annotation.PostConstruct;

@Configuration
public class CryptoConfig {
    @PostConstruct
    public void init() {
        Init.init();
    }

    @Bean
    public CryptoIO cryptoIO() {
        return CryptoIO.getInstance();
    }
}
