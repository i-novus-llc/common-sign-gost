package ru.i_novus.common.sign.service.api.model;

import io.swagger.annotations.ApiModel;
import lombok.Data;

import java.io.Serializable;

@Data
@ApiModel("Параметры подписи XML")
public class XmlSignParams implements Serializable {

    private String xmlDSigType;
}
