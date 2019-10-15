package ru.i_novus.common.sign.service.api.model;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import java.io.Serializable;
import java.util.Set;
import java.util.UUID;

@Data
@ApiModel("Результат улучшения подписи")
public class EnchanseResult implements Serializable {

    @ApiModelProperty("Заполняется, только если во входном запросе было заполнено поле x-callback значением идентификатора, присвоенного входящему запросу")
    private UUID resultId;

    @ApiModelProperty("Результат проверки подписей: true – все подписи верны, false – хотя бы одна подпись неверна")
    private boolean valid;

    @ApiModelProperty("Сообщение об ошибке обработки контейнера, если таковая произошла")
    private String message;

    @ApiModelProperty("Описание ошибки")
    private String error;

    @ApiModelProperty("Результаты проверки подписей в контейнере")
    private Set<SignatureData> signatures;

    @ApiModelProperty("Контейнер улучшенной ЭП")
    private byte[] enchancedSignature;
}
