package ru.i_novus.common.sign.service.api.model;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import java.io.Serializable;

@Data
@ApiModel ("Данные о субъекте/издателе")
public class CertificateAuthorityInfo implements Serializable {
    @ApiModelProperty("Общее имя (ФИО или название организации) (2.5.4.3)")
    private String commonName;

    @ApiModelProperty("Фамилия (2.5.4.4)")
    private String surname;

    @ApiModelProperty("Приобретенное имя (2.5.4.6)")
    private String givenName;

    @ApiModelProperty("Код страны (2.5.4.6)")
    private String countryName;

    @ApiModelProperty("Штат или область (2.5.4.8)")
    private String stateOrProvinceName;

    @ApiModelProperty("Наименование населенного пункта (2.5.4.7)")
    private String localityName;

    @ApiModelProperty("Название улицы, дома (2.5.4.9)")
    private String streetAddress;

    @ApiModelProperty("Наименование организации (2.5.4.10)")
    private String organizationName;

    @ApiModelProperty("Подразделение организации (2.5.4.11)")
    private String organizationUnitName;

    @ApiModelProperty("Должность (2.5.4.12)")
    private String title;

    @ApiModelProperty(value = "ОГРН (1.2.643.100.1)", name = "OGRN")
    private String ogrn;

    @ApiModelProperty(value = "СНИЛС (1.2.643.100.3)", name = "SNILS")
    private String snils;

    @ApiModelProperty(value = "ИНН (1.2.643.3.131.1.1)", name = "INN")
    private String inn;

    @ApiModelProperty(value = "Адрес электронной почты (1.2.840.113549.1.9.1)", name = "Email")
    private String email;
}
