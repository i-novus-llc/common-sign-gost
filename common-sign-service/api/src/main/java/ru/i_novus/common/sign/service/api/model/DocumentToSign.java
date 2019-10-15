package ru.i_novus.common.sign.service.api.model;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.math.BigInteger;

@Data
@ApiModel("Данные документа для подписи")
public class DocumentToSign implements Serializable {
    @NotNull
    @ApiModelProperty(value = "Серийный номер сертификата", required = true)
    private BigInteger serialNumber;

    @NotEmpty
    @ApiModelProperty(value = "Содержимое документа в Base64", required = true)
    private String docContent;
}
