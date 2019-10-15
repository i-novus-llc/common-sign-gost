package ru.i_novus.common.sign.service.api.model;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import java.io.Serializable;
import java.time.ZonedDateTime;

@Data
@ApiModel("Метка времени")
public class SignedTimestamp implements Serializable {

    @ApiModelProperty("Время подписания документа")
    private ZonedDateTime signatureDate;

    @ApiModelProperty(value = "Отпечаток сертификата подписанта")
    private String certificateThumbprint;
}
