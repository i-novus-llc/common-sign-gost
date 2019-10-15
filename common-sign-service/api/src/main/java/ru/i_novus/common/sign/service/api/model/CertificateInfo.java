package ru.i_novus.common.sign.service.api.model;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import java.io.Serializable;
import java.util.UUID;

@Data
@ApiModel("Cвойства сертификата")
public class CertificateInfo implements Serializable {
    @ApiModelProperty ("Заполняется, только если во входном запросе было заполнено поле x-callback значением идентификатора, присвоенного входящему запросу")
    private UUID resultId;

    @ApiModelProperty ("Результат проверки сертификата: true – сертификат действует, false – сертификат не действует")
    private boolean valid;

    @ApiModelProperty ("Текстовое описание причины признания сертификата недействующим")
    private String message;

    @ApiModelProperty ("Описание ошибки")
    private String error;

    @ApiModelProperty ("Данные сертификата")
    private CertificateData certificate;
}