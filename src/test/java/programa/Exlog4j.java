package programa;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExLog4j {
    private static final Logger LOG = LogManager.getLogger(ExLog4j.class);
    public static void main(String[] args) {
        LOG.info("hello from log4j2");
    }
}
