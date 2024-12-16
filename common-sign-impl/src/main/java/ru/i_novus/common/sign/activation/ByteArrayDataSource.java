package ru.i_novus.common.sign.activation;

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

import jakarta.activation.DataSource;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;

public class ByteArrayDataSource implements DataSource {
    private final String name;
    private final String contentType;
    private final byte[] buf;

    public ByteArrayDataSource(String name, String contentType, byte[] buf) {
        this.name = name;
        this.contentType = contentType;
        this.buf = buf;
    }

    @Override
    public String getContentType() {
        if (contentType == null)
            return "application/octet-stream";
        return contentType;
    }

    @Override
    public InputStream getInputStream() {
        return new ByteArrayInputStream(buf);
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public OutputStream getOutputStream() {
        throw new UnsupportedOperationException("unsupported");
    }
}
