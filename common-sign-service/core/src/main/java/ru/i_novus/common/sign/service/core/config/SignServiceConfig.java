package ru.i_novus.common.sign.service.core.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "sign.service")
public class SignServiceConfig {

    private Storage storage = new Storage();

    @Getter
    @Setter
    public static class Storage {
        private String type;
        private String path;
        private Map<String, String> passwords = new HashMap<>();
    }
}
