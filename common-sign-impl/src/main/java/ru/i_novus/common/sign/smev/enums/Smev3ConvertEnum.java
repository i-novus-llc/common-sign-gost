package ru.i_novus.common.sign.smev.enums;

public enum Smev3ConvertEnum {

    GET_REQUEST_REQUEST("GetRequestRequest"),

    GET_RESPONSE_REQUEST("GetResponseRequest"),

    ACK_REQUEST("AckRequest"),

    SEND_REQUEST_REQUEST("SendRequestRequest"),

    SEND_RESPONSE_REQUEST("SendResponseRequest"),

    GET_INCOMING_QUEUE_STATISTICS_REQUEST("GetIncomingQueueStatisticsRequest"),

    GET_STATUS_REQUEST("GetStatusRequest");

    String convertName;

    Smev3ConvertEnum(final String convertName) {
        this.convertName = convertName;
    }

    public String getConvertName() {
        return convertName;
    }

    public static Smev3ConvertEnum fromValue(String value) throws IllegalArgumentException {
        for(Smev3ConvertEnum e: Smev3ConvertEnum.values()) {
            if(e.convertName.equals(value)) {
                return e;
            }
        }
        return null;
    }
}
