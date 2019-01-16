package ru.i_novus.common.sign.util;

import ru.i_novus.common.sign.exception.CommonSignRuntimeException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class IOUtil {

    private IOUtil() {
        throw new InstantiationError("Must not instantiate this class");
    }

    public static void fileDelete(Path path){
        try {
            Files.delete(path);
        } catch (IOException e) {
            throw new CommonSignRuntimeException(e);
        }
    }

    public static void fileDelete(String path){
        fileDelete(Paths.get(path));
    }

    public static Path createTempDirectory(String prefix){
        try {
            return Files.createTempDirectory(prefix);
        } catch (IOException e) {
            throw new CommonSignRuntimeException(e);
        }
    }
}
