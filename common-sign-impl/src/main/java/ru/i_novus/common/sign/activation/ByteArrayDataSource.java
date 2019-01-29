package ru.i_novus.common.sign.activation;

import javax.activation.DataSource;
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