package ru.i_novus.common.sign.service.api.rest;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import ru.i_novus.common.sign.service.api.model.SignatureResult;
import ru.i_novus.common.sign.service.api.model.ValidateResult;
import ru.i_novus.common.sign.service.api.model.XmlDocumentToSign;

import javax.validation.Valid;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

@Api(value = "Работа с XML")
@Path("xmldsig")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public interface XmlRest {
    @POST
    @Path("verify")
    @ApiOperation(value = "Полная проверка ЭП в формате XMLDsig")
    ValidateResult verify();

    @POST
    @Path("verifyhash")
    @ApiOperation(value = "Проверка неизменности документа (проверка хэша документа), подписанного ЭП формата XMLDsig")
    ValidateResult verifyhash();

    @POST
    @Path("sign")
    @ApiOperation(value = "Электронная подпись XML документа в формате XMLDsig" )
    SignatureResult sign(@Valid @ApiParam XmlDocumentToSign params);
}
