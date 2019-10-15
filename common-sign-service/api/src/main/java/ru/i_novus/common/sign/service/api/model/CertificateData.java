package ru.i_novus.common.sign.service.api.model;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import java.io.Serializable;
import java.time.ZonedDateTime;
import java.util.Set;

@Data
@ApiModel("Данные сертификата")
public class CertificateData implements Serializable {
    @ApiModelProperty("Серийный номер сертификата")
    private String serialNumber;

    @ApiModelProperty("Дата начала действия")
    private ZonedDateTime startdate;

    @ApiModelProperty("Дата окончания действия")
    private ZonedDateTime enddate;

    @ApiModelProperty("Алгоритм подписи")
    private String algorithmIdentifier;

    @ApiModelProperty("Хэш-алгоритм подписи")
    private String hashAlgorithmIdentifier;

    @ApiModelProperty("Версия формата сертификата")
    private int version;

    @ApiModelProperty(value = "Область использования ключа проверки ЭП (2.5.29.15):\n" +
            "- Электронная подпись (SigitalSignature),\n" +
            "- Неотрекаемость (ContentCommitment),\n" +
            "- Шифрование ключей (KeyEncipherment),\n" +
            "- Шифрование данных (DataEncipherment),\n" +
            "- Согласование ключей (KeyAgreement),\n" +
            "- Проверка подписей под сертификатами (KeyCertSign),\n" +
            "- Проверка подписей под списками отозванных сертификатов (CrlSign),\n" +
            "- Шифрование данных в процессе формирования ключей (EncipherOnly),\n" +
            "- Расшифрование данных в процессе согласования ключей (DecipherOnly).",
            allowableValues = "SigitalSignature, ContentCommitment, KeyEncipherment, DataEncipherment, " +
                    "KeyAgreement, KeyCertSign, CrlSign, EncipherOnly, DecipherOnly")
    private Set<String> keyUsage;


    @ApiModelProperty("Oid-ы из расширения «Улучшенный ключ» (2.5.29.37)")
    private Set<String> extendedKeyUsage;

    @ApiModelProperty(value = "Статус электронной подписи УЦ под сертификатом", required = false)
    private String caSignatureStatus;

    @ApiModelProperty(value = "Адреса точек распространения списков отзывов (2.5.29.31)")
    private String crlDistributionPoints;

    @ApiModelProperty(value = "Средство электронной подписи владельца (1.2.643.100.111)")
    private String signatureMethod;

    @ApiModelProperty(value = "Средства электронной подписи УЦ издателя (1.2.643.100.112)")
    private String caSignatureMethod;

    @ApiModelProperty(value = "Класс средств ЭП владельца сертификата (2.5.29.32):\n" +
            "- 1.2.643.100.113.1 - класс средства ЭП КС1,\n" +
            "- 1.2.643.100.113.2 - класс средства ЭП КС2,\n" +
            "- 1.2.643.100.113.3 - класс средства ЭП КС3,\n" +
            "- 1.2.643.100.113.4 - класс средства ЭП КВ1,\n" +
            "- 1.2.643.100.113.5 - класс средства ЭП КВ2,\n" +
            "- 1.2.643.100.113.6 - класс средства ЭП КА1",
            allowableValues = "1.2.643.100.113.1, 1.2.643.100.113.2, 1.2.643.100.113.3, 1.2.643.100.113.4, 1.2.643.100.113.5, 1.2.643.100.113.6")
    private String certificatePolicies;

    @ApiModelProperty(value = "Данные об издателе сертификата")
    private CertificateAuthorityInfo issuer;

    @ApiModelProperty(value = "Данные о субъекте сертификата")
    private CertificateAuthorityInfo subject;
}