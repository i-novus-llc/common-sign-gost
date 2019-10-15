package ru.i_novus.common.sign.service.api.model;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.io.Serializable;

@EqualsAndHashCode(callSuper = true)
@Data
@ApiModel ("Данные XML-документа для подписи")
public class XmlDocumentToSign extends DocumentToSign implements Serializable {

    @ApiModelProperty("Параметры подписи")
    private XmlSignParams signParams;
}
