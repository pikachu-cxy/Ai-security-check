// Synthetic upload paths; bytes are data, not destination names.
import org.springframework.web.multipart.MultipartFile;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

class UploadPathFixture {
    void originalFilename(MultipartFile upload) throws Exception {
        File destination = new File("uploads", upload.getOriginalFilename());
        // ruleid: ai-security.java.spring-upload-path
        upload.transferTo(destination);
    }

    void resolvedFilename(MultipartFile upload) throws Exception {
        Path destination = Paths.get("uploads").resolve(upload.getOriginalFilename());
        // ruleid: ai-security.java.spring-upload-path
        upload.transferTo(destination);
    }

    void normalizationAlone(MultipartFile upload) throws Exception {
        Path destination = Paths.get("uploads").resolve(upload.getOriginalFilename()).normalize();
        // ruleid: ai-security.java.spring-upload-path
        upload.transferTo(destination);
    }

    void requestedDestination(HttpServletRequest request, MultipartFile upload) throws Exception {
        // ruleid: ai-security.java.spring-upload-path
        upload.transferTo(new File(request.getParameter("path")));
    }

    void fixedDestination(MultipartFile upload) throws Exception {
        String ignored = upload.getOriginalFilename();
        // ok: ai-security.java.spring-upload-path
        upload.transferTo(new File("uploads", "server-selected.bin"));
    }

    void uploadBytesNotPath(MultipartFile upload) throws Exception {
        byte[] data = upload.getBytes();
        // ok: ai-security.java.spring-upload-path
        java.nio.file.Files.write(Paths.get("uploads", "fixed.bin"), data);
    }

    void exactSelection(MultipartFile upload) throws Exception {
        String requested = upload.getOriginalFilename();
        String name = "first.bin";
        if ("second".equals(requested)) name = "second.bin";
        // ok: ai-security.java.spring-upload-path
        upload.transferTo(new File("uploads", name));
    }

    void lexicalContainment(MultipartFile upload) throws Exception {
        Path base = Paths.get("uploads").toAbsolutePath().normalize();
        Path destination = base.resolve(upload.getOriginalFilename()).normalize();
        if (!destination.startsWith(base)) { throw new IllegalArgumentException(); }
        // ok: ai-security.java.spring-upload-path
        upload.transferTo(destination);
    }

    void checkedPathOverwritten(MultipartFile upload) throws Exception {
        Path base = Paths.get("uploads").toAbsolutePath().normalize();
        Path destination = base.resolve(upload.getOriginalFilename()).normalize();
        if (!destination.startsWith(base)) { throw new IllegalArgumentException(); }
        destination = Paths.get(upload.getOriginalFilename());
        // ruleid: ai-security.java.spring-upload-path
        upload.transferTo(destination);
    }

    void containmentExceptionCaught(MultipartFile upload) throws Exception {
        Path base = Paths.get("uploads").toAbsolutePath().normalize();
        Path destination = base.resolve(upload.getOriginalFilename()).normalize();
        try {
            if (!destination.startsWith(base)) { throw new IllegalArgumentException(); }
        } catch (IllegalArgumentException ignored) {
            // The handler swallows the rejection and continues to the write.
        }
        // ruleid: ai-security.java.spring-upload-path
        upload.transferTo(destination);
    }
}
