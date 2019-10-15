package ru.i_novus.common.sign.service.api.model;

import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import java.io.Serializable;

@Data
public class CommonResponse implements Serializable {
    @ApiModelProperty("Сообщение об ошибке обработки контейнера, если таковая произошла")
    private String message;

    @ApiModelProperty("Описание ошибки")
    private String error;
}
