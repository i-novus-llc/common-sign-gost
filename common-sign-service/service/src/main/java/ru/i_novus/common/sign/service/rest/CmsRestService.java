package ru.i_novus.common.sign.service.rest;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.NotImplementedException;
import org.springframework.stereotype.Controller;
import ru.i_novus.common.sign.service.api.model.EnchanseResult;
import ru.i_novus.common.sign.service.api.model.ValidateResult;
import ru.i_novus.common.sign.service.api.rest.CmsRest;

@Slf4j
@Controller
public class CmsRestService implements CmsRest {
    @Override
    public ValidateResult verify() {
        throw new NotImplementedException("The feature is not implemented yet");
    }

    @Override
    public ValidateResult verifyhash() {
        throw new NotImplementedException("The feature is not implemented yet");
    }

    @Override
    public EnchanseResult enhance() {
        throw new NotImplementedException("The feature is not implemented yet");
    }
}
