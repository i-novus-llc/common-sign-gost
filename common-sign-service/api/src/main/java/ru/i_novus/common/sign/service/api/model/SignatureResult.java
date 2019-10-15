package ru.i_novus.common.sign.service.api.model;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.io.Serializable;

@EqualsAndHashCode(callSuper = true)
@Data
@ApiModel("Результат подписи")
public class SignatureResult extends CommonResponse implements Serializable {
    @ApiModelProperty("Подписанные данные")
    private byte[] signedData;
}
