package ru.i_novus.common.sign.service.api.rest;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import ru.i_novus.common.sign.service.api.model.EnchanseResult;
import ru.i_novus.common.sign.service.api.model.ValidateResult;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

@Api(value = "Сервис подписи, формат CMS")
@Path("cms")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public interface CmsRest {
    @POST
    @Path("verify")
    @ApiOperation(value = "Полная проверка ЭП в формате CMS или CAdES")
    ValidateResult verify();

    @POST
    @Path("verifyhash")
    @ApiOperation(value = "Проверка неизменности документа (проверка хэша документа), подписанного ЭП формата CMS или CAdES")
    ValidateResult verifyhash();

    @POST
    @Path("enhance")
    @ApiOperation(value = "Улучшение подписи до формата CAdES X-Long")
    EnchanseResult enhance();
}