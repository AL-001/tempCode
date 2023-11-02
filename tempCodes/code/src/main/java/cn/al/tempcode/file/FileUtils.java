package cn.al.tempcode.file;

import java.io.File;
import java.net.URISyntaxException;

public class FileUtils {
    public static File getFileInClassPath(String filePath){
        try {
            return new File(FileUtils.class.getClassLoader().getResource(filePath).toURI());
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }
}
