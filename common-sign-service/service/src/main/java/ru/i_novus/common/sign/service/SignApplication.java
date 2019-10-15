package ru.i_novus.common.sign.service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import ru.i_novus.common.sign.service.core.config.CryptoConfig;

@SpringBootApplication
@ComponentScan(value = "ru.i_novus.common.sign.service")
@ImportAutoConfiguration(classes = { CryptoConfig.class} )
public class SignApplication {
    public static void main(String[] args) {
        System.setProperty("javax.xml.soap.SAAJMetaFactory", "com.sun.xml.messaging.saaj.soap.SAAJMetaFactoryImpl");
        SpringApplication.run(SignApplication.class, args);
    }
}
