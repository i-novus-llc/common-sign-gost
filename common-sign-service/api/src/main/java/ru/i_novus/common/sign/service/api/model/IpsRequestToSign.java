package ru.i_novus.common.sign.service.api.model;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;
import lombok.EqualsAndHashCode;

import javax.validation.constraints.NotBlank;
import java.io.Serializable;

@EqualsAndHashCode(callSuper = true)
@Data
@ApiModel("Данные запроса в сервис ИПС")
public class IpsRequestToSign extends DocumentToSign implements Serializable {
    @NotBlank
    @ApiModelProperty(value = "Адрес, на который направляется запрос. Будет прописан в теге http://www.w3.org/2005/08/addressing:To", required = true)
    private String soapService;

    @NotBlank
    @ApiModelProperty(value = "Выполняемый SOAP Action. Будет прописан в теге http://www.w3.org/2005/08/addressing:Action", required = true)
    private String soapAction;

    @NotBlank
    @ApiModelProperty(value = "Идентификатор системы - клиента ИПС. Будет прописан в теге http://egisz.rosminzdrav.ru:clientEntityId", required = true)
    private String clientEntityId;
}
