package ru.i_novus.common.sign.service.core.impl;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.*;

@Slf4j
public class KeystorageWatchService implements Runnable {
    private WatchService watchService;

    private FileKeystoreServiceImpl keystoreService;

    public KeystorageWatchService(Path path, FileKeystoreServiceImpl keystoreService) throws IOException {
        this.keystoreService = keystoreService;
        watchService = FileSystems.getDefault().newWatchService();
        path.register(watchService, StandardWatchEventKinds.ENTRY_CREATE,
                StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_DELETE);
    }

    @Override
    public void run() {
        WatchKey key;

        try {
            while ((key = watchService.take()) != null) {
                key.pollEvents().forEach(event -> {
                    try {
                        processEvent(event);
                    } catch (RuntimeException e) {
                        logger.error("Cannot process event '{}'", event, e);
                    }
                });
                key.reset();
            }
        } catch (InterruptedException e) {
            logger.debug("KeystorageWatchService is interrupted");
            Thread.currentThread().interrupt();
        }
    }

    private void processEvent(WatchEvent<?> event) {
        switch(event.kind().name()) {
            case "ENTRY_CREATE": {
                created(event);
                break;
            }
            case "ENTRY_MODIFY": {
                modified(event);
                break;
            }
            case "ENTRY_DELETE": {
                deleted(event);
                break;
            }
            default:
                logger.info("Unknown event type: {}", event.kind().name());
        }
    }

    private void created(WatchEvent<?> event) {
        Path path = (Path)event.context();
        if (path.toFile().isFile())
            keystoreService.addKey(path);
    }

    private void modified(WatchEvent<?> event) {
        Path path = (Path)event.context();
        if (path.toFile().isFile())
            keystoreService.modifyKey(path);
    }

    private void deleted(WatchEvent<?> event) {
        Path path = (Path)event.context();
        keystoreService.removeKey(path);
    }
}
