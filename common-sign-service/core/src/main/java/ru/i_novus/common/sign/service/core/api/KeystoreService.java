package ru.i_novus.common.sign.service.core.api;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Optional;

/**
 * Сервис для работы с хранилищем ключей ЭП
 */
public interface KeystoreService {
    /**
     * Получение ключа из хранилища по серийному номеру сертификата
     *
     * @param certificateSerialNumber серийный номер сертификата
     * @return найденная ключевая пара
     */
    Optional<PrivateKey> getPrivateKey(BigInteger certificateSerialNumber);

    /**
     * Получение сертификата их хранилища по его серийному номеру
     *
     * @param serialNumber серийный номер сертификата
     * @return найденный сертификат
     */
    Optional<X509Certificate> getCertificate(BigInteger serialNumber);
}
