package utils;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Description
 */
@Retention(RetentionPolicy.RUNTIME)
public @interface Description {
    String value();
}
