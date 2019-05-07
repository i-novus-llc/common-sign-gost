package ru.i_novus.common.sign.smev.enums;

/*-
 * -----------------------------------------------------------------
 * common-sign-gost
 * -----------------------------------------------------------------
 * Copyright (C) 2018 - 2019 I-Novus LLC
 * -----------------------------------------------------------------
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * -----------------------------------------------------------------
 */

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

    public static Smev3ConvertEnum fromValue(String value) throws IllegalArgumentException {
        for(Smev3ConvertEnum e: Smev3ConvertEnum.values()) {
            if(e.convertName.equals(value)) {
                return e;
            }
        }
        return null;
    }
}
