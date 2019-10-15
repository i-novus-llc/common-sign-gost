package ru.i_novus.common.sign.service.api.rest;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import ru.i_novus.common.sign.service.api.model.ValidateResult;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;


@Api(value = "Сервис работы с сертификатами")
@Path("certificate")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public interface CertificateRest {

    @POST
    @Path("verify")
    @ApiOperation(value = "Получение данных о сертификате ключа проверки ЭП")
    ValidateResult verify();

}