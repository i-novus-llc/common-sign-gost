package ru.i_novus.common.sign.service.api.rest;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import ru.i_novus.common.sign.service.api.model.DocumentToSign;
import ru.i_novus.common.sign.service.api.model.IpsRequestToSign;
import ru.i_novus.common.sign.service.api.model.SignatureResult;

import javax.validation.Valid;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

@Api(value = "Сервис подписи сообщений, направляемых в Интенграционную подсистему (ИПС) МЗ РФ")
@Path("ips")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public interface IpsRest {
    @POST
    @Path("signRequest")
    @ApiOperation(value = "Подпись запроса, направляемого в ИПС")
    SignatureResult signIpsRequest(@Valid @ApiParam IpsRequestToSign document);

    @POST
    @Path("signResponse")
    @ApiOperation(value = "Подпись асинхронного ответа на запрос, направляемого в ИПС")
    SignatureResult signIpsResponse(@Valid @ApiParam DocumentToSign document);
}
