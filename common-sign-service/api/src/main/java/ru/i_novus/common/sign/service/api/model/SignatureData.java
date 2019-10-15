package ru.i_novus.common.sign.service.api.model;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import java.io.Serializable;
import java.time.ZonedDateTime;
import java.util.Set;

@Data
@ApiModel("Данные о подписях в контейнере")
public class SignatureData implements Serializable {

    @ApiModelProperty(value = "Тип ЭП:\n" +
            "- Усиленная неквалифицированная (StrongUnqualified),\n" +
            "- Усиленная квалифицированная (StrongQualified),\n" +
            "- Улучшенная квалифицированная (EnhancedUnqualified),\n" +
            "- Улучшенная неквалифицированная (EnhancedQualified)",
            allowableValues = "StrongUnqualified, StrongQualified, EnhancedUnqualified, EnhancedQualified")
    private String type;

    @ApiModelProperty(value = "Формат ЭП", allowableValues = "CMS, CAdES, XMLDsig")
    private String format;

    @ApiModelProperty(value = "Результат проверки: true – подпись верна, false – подпись неверна")
    private boolean valid;

    @ApiModelProperty(value = "Причина признания подписи неверной:\n" +
            "- Документ изменен,\n" +
            "- Нарушена целостность ЭП,\n" +
            "- Сертификат просрочен,\n" +
            "- Сертификат отозван,\n" +
            "- Невозможно подтвердить действительность сертификата,\n" +
            "- Невозможно построить цепочку сертификации,\n" +
            "- Нераспознанная ошибка")
    private String invalidationReason;

    @ApiModelProperty(value = "Текстовое описание причины признания подписи невалидной")
    private String message;

    @ApiModelProperty(value = "Описание ошибки")
    private String error;

    @ApiModelProperty(value = "Время подписания документа")
    private ZonedDateTime signatureDate;

    @ApiModelProperty(value = "Отпечаток сертификата подписанта")
    private String certificateThumbprint;

    @ApiModelProperty(value = "Данные сертификатов, использованных при создании подписи")
    private Set<CertificateData> certificates;

    @ApiModelProperty(value = "Метки времени")
    private Set<SignedTimestamp> signedTimestamps;
}
